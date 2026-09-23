/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Deterministic, segment-aware mutation engine for PASETO tokens. Mutations are derived from a
 * valid token by decoding the payload segment, altering bytes at understood offsets (nonce,
 * ciphertext or message, authentication tag or signature) and re-encoding, so that rejections
 * exercise the intended processing stage instead of degenerating into base64 parse failures.
 */
public final class TokenMutations {

  private static final String[] VERSION_HEADERS = {"v1", "v2", "v3", "v4"};

  private TokenMutations() {}

  /**
   * Mutations for a {@code local} token whose payload is {@code nonce || ciphertext || tag}.
   *
   * @param nonceBytes nonce length of the version (v1/v3: 32, v2: 24, v4: 32)
   * @param tagBytes authentication tag length of the version (v1/v3: 48, v2: 16, v4: 32)
   * @param assertionsSupported whether the version authenticates an implicit assertion
   */
  public static List<TokenMutation> forLocalVector(
      String vectorId,
      String token,
      String footer,
      String implicitAssertion,
      int nonceBytes,
      int tagBytes,
      boolean assertionsSupported) {
    return forVector(
        vectorId,
        Purpose.PURPOSE_LOCAL,
        token,
        footer,
        implicitAssertion,
        nonceBytes,
        tagBytes,
        assertionsSupported);
  }

  /**
   * Mutations for a {@code public} token whose payload is {@code message || signature}.
   *
   * @param signatureBytes signature length of the version (v1: 256, v2: 64, v3: 96, v4: 64)
   * @param assertionsSupported whether the version authenticates an implicit assertion
   */
  public static List<TokenMutation> forPublicVector(
      String vectorId,
      String token,
      String footer,
      String implicitAssertion,
      int signatureBytes,
      boolean assertionsSupported) {
    return forVector(
        vectorId,
        Purpose.PURPOSE_PUBLIC,
        token,
        footer,
        implicitAssertion,
        0,
        signatureBytes,
        assertionsSupported);
  }

  /**
   * Payload-length table from 0 bytes up to one byte past the minimum legitimate payload
   * ({@code nonce + tag} or {@code signature}), proving each side of the threshold is rejected
   * at the expected stage.
   */
  public static List<TokenMutation> lengthTable(
      String vectorId,
      Purpose purpose,
      String token,
      String footer,
      String implicitAssertion,
      int minimumBytes) {
    String[] parts = token.split("\\.", -1);
    byte[] body = decode(parts[2]);
    List<TokenMutation> mutations = new ArrayList<>();
    for (int length = 0; length <= minimumBytes + 1; length++) {
      if (length == body.length) {
        continue;
      }
      MutationStage stage =
          length == 0
              ? MutationStage.STRUCTURE
              : length < minimumBytes ? MutationStage.LENGTH : MutationStage.AUTHENTICATION;
      mutations.add(
          new TokenMutation(
              vectorId,
              "payload length " + length + " bytes (minimum " + minimumBytes + ")",
              stage,
              purpose,
              replacePayload(parts, encode(Arrays.copyOf(body, length))),
              footer,
              implicitAssertion));
    }
    return mutations;
  }

  /** Number of mutations per stage, used to prove every stage is hit at least once. */
  public static Map<MutationStage, Long> coverage(List<TokenMutation> mutations) {
    return mutations.stream()
        .collect(
            Collectors.groupingBy(
                TokenMutation::stage,
                () -> new EnumMap<>(MutationStage.class),
                Collectors.counting()));
  }

  private static List<TokenMutation> forVector(
      String vectorId,
      Purpose purpose,
      String token,
      String footer,
      String implicitAssertion,
      int nonceBytes,
      int tagBytes,
      boolean assertionsSupported) {
    List<TokenMutation> mutations = new ArrayList<>();
    String[] parts = token.split("\\.", -1);
    String version = parts[0];
    String purposeLabel = parts[1];
    String header = version + "." + purposeLabel + ".";
    byte[] body = decode(parts[2]);
    boolean hasFooter = parts.length == 4;
    int minimumBytes = nonceBytes + tagBytes;

    headerMutations(
        mutations, vectorId, purpose, token, footer, implicitAssertion, version, purposeLabel);
    structureMutations(
        mutations, vectorId, purpose, token, footer, implicitAssertion, parts, hasFooter);
    footerMutations(
        mutations, vectorId, purpose, token, footer, implicitAssertion, parts, header, hasFooter);
    encodingMutations(
        mutations, vectorId, purpose, footer, implicitAssertion, parts, header, hasFooter);
    authenticationMutations(
        mutations, vectorId, purpose, footer, implicitAssertion, parts, body, nonceBytes,
        tagBytes, minimumBytes);
    if (assertionsSupported) {
      assertionMutations(mutations, vectorId, purpose, token, footer, implicitAssertion);
    }
    return mutations;
  }

  private static void headerMutations(
      List<TokenMutation> mutations,
      String vectorId,
      Purpose purpose,
      String token,
      String footer,
      String implicitAssertion,
      String version,
      String purposeLabel) {
    for (String other : VERSION_HEADERS) {
      if (!other.equals(version)) {
        add(
            mutations, vectorId, "header version " + version + "->" + other, MutationStage.HEADER,
            purpose, other + token.substring(version.length()), footer, implicitAssertion);
      }
    }
    String otherPurpose = purposeLabel.equals("local") ? "public" : "local";
    add(
        mutations, vectorId, "header purpose " + purposeLabel + "->" + otherPurpose,
        MutationStage.HEADER, purpose,
        version + "." + otherPurpose + token.substring((version + "." + purposeLabel).length()),
        footer, implicitAssertion);
    add(
        mutations, vectorId, "header version uppercased", MutationStage.HEADER, purpose,
        version.toUpperCase(Locale.ROOT) + token.substring(version.length()), footer,
        implicitAssertion);
  }

  private static void structureMutations(
      List<TokenMutation> mutations,
      String vectorId,
      Purpose purpose,
      String token,
      String footer,
      String implicitAssertion,
      String[] parts,
      boolean hasFooter) {
    String withoutFooter = parts[0] + "." + parts[1] + "." + parts[2];
    if (hasFooter) {
      add(mutations, vectorId, "footer segment dropped", MutationStage.STRUCTURE, purpose,
          withoutFooter, footer, implicitAssertion);
      add(mutations, vectorId, "footer segment dropped, no footer expected",
          MutationStage.AUTHENTICATION, purpose, withoutFooter, "", implicitAssertion);
      add(mutations, vectorId, "extra segment appended", MutationStage.STRUCTURE, purpose,
          token + ".extra", footer, implicitAssertion);
    } else {
      add(mutations, vectorId, "empty footer segment appended", MutationStage.STRUCTURE, purpose,
          token + ".", footer, implicitAssertion);
      add(mutations, vectorId, "unexpected footer segment appended", MutationStage.STRUCTURE,
          purpose, token + ".eA", footer, implicitAssertion);
      add(mutations, vectorId, "footer expected but token has none", MutationStage.STRUCTURE,
          purpose, token, "unexpected-footer", implicitAssertion);
    }
    String emptyPayload = parts[0] + "." + parts[1] + "." + (hasFooter ? "." + parts[3] : "");
    add(mutations, vectorId, "payload segment emptied", MutationStage.STRUCTURE, purpose,
        emptyPayload, footer, implicitAssertion);
  }

  private static void footerMutations(
      List<TokenMutation> mutations,
      String vectorId,
      Purpose purpose,
      String token,
      String footer,
      String implicitAssertion,
      String[] parts,
      String header,
      boolean hasFooter) {
    if (!hasFooter) {
      return;
    }
    String alteredFooter = alterFirstCharacter(footer);
    String tokenWithAlteredFooter = header + parts[2] + "." + encode(alteredFooter.getBytes(UTF_8));
    add(mutations, vectorId, "footer character altered @0, original footer expected",
        MutationStage.FOOTER, purpose, tokenWithAlteredFooter, footer, implicitAssertion);
    add(mutations, vectorId, "footer character altered @0, altered footer expected",
        MutationStage.AUTHENTICATION, purpose, tokenWithAlteredFooter, alteredFooter,
        implicitAssertion);
    add(mutations, vectorId, "wrong footer expected", MutationStage.FOOTER, purpose, token,
        footer + "-altered", implicitAssertion);
  }

  private static void encodingMutations(
      List<TokenMutation> mutations,
      String vectorId,
      Purpose purpose,
      String footer,
      String implicitAssertion,
      String[] parts,
      String header,
      boolean hasFooter) {
    add(mutations, vectorId, "payload padding '=' appended", MutationStage.ENCODING, purpose,
        replacePayload(parts, parts[2] + "="), footer, implicitAssertion);
    add(mutations, vectorId, "payload invalid character @0", MutationStage.ENCODING, purpose,
        replacePayload(parts, "!" + parts[2].substring(1)), footer, implicitAssertion);
    if (hasFooter) {
      add(mutations, vectorId, "footer padding '=' appended", MutationStage.ENCODING, purpose,
          header + parts[2] + "." + parts[3] + "=", footer, implicitAssertion);
      add(mutations, vectorId, "footer invalid character @0", MutationStage.ENCODING, purpose,
          header + parts[2] + "." + "!" + parts[3].substring(1), footer, implicitAssertion);
    }
  }

  private static void authenticationMutations(
      List<TokenMutation> mutations,
      String vectorId,
      Purpose purpose,
      String footer,
      String implicitAssertion,
      String[] parts,
      byte[] body,
      int nonceBytes,
      int tagBytes,
      int minimumBytes) {
    if (nonceBytes > 0) {
      addBitFlip(mutations, vectorId, purpose, footer, implicitAssertion, parts, body, 0,
          "nonce");
      addBitFlip(mutations, vectorId, purpose, footer, implicitAssertion, parts, body,
          nonceBytes - 1, "nonce");
    }
    String contentLabel = purpose == Purpose.PURPOSE_LOCAL ? "ciphertext" : "message";
    int contentEnd = body.length - tagBytes;
    if (contentEnd > nonceBytes) {
      addBitFlip(mutations, vectorId, purpose, footer, implicitAssertion, parts, body, nonceBytes,
          contentLabel);
      addBitFlip(mutations, vectorId, purpose, footer, implicitAssertion, parts, body,
          contentEnd - 1, contentLabel);
    }
    String tagLabel = purpose == Purpose.PURPOSE_LOCAL ? "tag" : "signature";
    addBitFlip(mutations, vectorId, purpose, footer, implicitAssertion, parts, body,
        body.length - tagBytes, tagLabel);
    addBitFlip(mutations, vectorId, purpose, footer, implicitAssertion, parts, body,
        body.length - 1, tagLabel);

    int truncated = body.length - 1;
    MutationStage truncateStage =
        truncated < minimumBytes ? MutationStage.LENGTH : MutationStage.AUTHENTICATION;
    add(mutations, vectorId, "payload truncated to " + truncated + " bytes", truncateStage,
        purpose, replacePayload(parts, encode(Arrays.copyOf(body, truncated))), footer,
        implicitAssertion);

    byte[] extended = Arrays.copyOf(body, body.length + 1);
    add(mutations, vectorId, "payload extended +1 byte", MutationStage.AUTHENTICATION, purpose,
        replacePayload(parts, encode(extended)), footer, implicitAssertion);
  }

  private static void assertionMutations(
      List<TokenMutation> mutations,
      String vectorId,
      Purpose purpose,
      String token,
      String footer,
      String implicitAssertion) {
    if (implicitAssertion.isEmpty()) {
      add(mutations, vectorId, "implicit assertion injected", MutationStage.AUTHENTICATION,
          purpose, token, footer, "injected-assertion");
    } else {
      add(mutations, vectorId, "implicit assertion dropped", MutationStage.AUTHENTICATION,
          purpose, token, footer, "");
      add(mutations, vectorId, "implicit assertion altered", MutationStage.AUTHENTICATION,
          purpose, token, footer, implicitAssertion + "-altered");
    }
  }

  private static void addBitFlip(
      List<TokenMutation> mutations,
      String vectorId,
      Purpose purpose,
      String footer,
      String implicitAssertion,
      String[] parts,
      byte[] body,
      int byteOffset,
      String region) {
    byte[] mutated = body.clone();
    mutated[byteOffset] ^= 0x01;
    add(mutations, vectorId, region + " bit-flip @byte " + byteOffset,
        MutationStage.AUTHENTICATION, purpose, replacePayload(parts, encode(mutated)), footer,
        implicitAssertion);
  }

  private static void add(
      List<TokenMutation> mutations,
      String vectorId,
      String label,
      MutationStage stage,
      Purpose purpose,
      String token,
      String footer,
      String implicitAssertion) {
    mutations.add(
        new TokenMutation(vectorId, label, stage, purpose, token, footer, implicitAssertion));
  }

  private static String replacePayload(String[] parts, String payload) {
    StringBuilder rebuilt =
        new StringBuilder(parts[0]).append('.').append(parts[1]).append('.').append(payload);
    if (parts.length == 4) {
      rebuilt.append('.').append(parts[3]);
    }
    return rebuilt.toString();
  }

  private static String alterFirstCharacter(String value) {
    char first = value.charAt(0);
    return (first == 'A' ? 'B' : 'A') + value.substring(1);
  }

  private static byte[] decode(String segment) {
    return Base64.getUrlDecoder().decode(segment);
  }

  private static String encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
