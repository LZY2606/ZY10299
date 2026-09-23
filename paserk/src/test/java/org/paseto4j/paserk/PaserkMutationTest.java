/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.HexToBytes;
import org.paseto4j.commons.MutationStage;
import org.paseto4j.commons.TestVectors;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.keys.KeyEncoding;
import org.paseto4j.paserk.operations.key.SealingSecretKey;

/**
 * Deterministic mutation suite for PASERK strings, kept separate from the token and Unicode
 * cases. Structural mutations are applied to every supported type; authentication mutations
 * only to types whose payload is authenticated (wrap, seal, password wrap), because a bit-flip
 * inside a raw key payload legitimately decodes to another valid key. Display names carry the
 * vector id and mutation position, never the PASERK itself (it contains key material).
 */
class PaserkMutationTest {

  private enum Kind {
    LOCAL,
    PUBLIC,
    SECRET,
    LOCAL_WRAP,
    LOCAL_PW,
    SEAL
  }

  private record PaserkMutation(
      String vectorId, String label, MutationStage stage, Kind kind, Version version,
      String paserk, String auxiliary) {
    String display() {
      return vectorId + " :: " + label;
    }
  }

  private static final String ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  private static final List<PaserkMutation> MUTATIONS = new ArrayList<>();

  static {
    try {
      setUp();
    } catch (IOException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  private static void setUp() throws IOException {
    addRawKeyVectors("k3.local.json", Kind.LOCAL, Version.V3);
    addRawKeyVectors("k4.local.json", Kind.LOCAL, Version.V4);
    addRawKeyVectors("k3.public.json", Kind.PUBLIC, Version.V3);
    addRawKeyVectors("k4.public.json", Kind.PUBLIC, Version.V4);
    addRawKeyVectors("k3.secret.json", Kind.SECRET, Version.V3);
    addRawKeyVectors("k4.secret.json", Kind.SECRET, Version.V4);
    addAuthenticatedVectors("k3.local-wrap.pie.json", Kind.LOCAL_WRAP, Version.V3);
    addAuthenticatedVectors("k4.local-wrap.pie.json", Kind.LOCAL_WRAP, Version.V4);
    addAuthenticatedVectors("k3.local-pw.json", Kind.LOCAL_PW, Version.V3);
    addAuthenticatedVectors("k4.local-pw.json", Kind.LOCAL_PW, Version.V4);
    addAuthenticatedVectors("k3.seal.json", Kind.SEAL, Version.V3);
    addAuthenticatedVectors("k4.seal.json", Kind.SEAL, Version.V4);
  }

  private static void addRawKeyVectors(String resource, Kind kind, Version version)
      throws IOException {
    TestVectors.TestVector vector = firstSuccessful(resource);
    String paserk = vector.paserk;
    structuralMutations(vector.name, kind, version, paserk, null, true);
  }

  private static void addAuthenticatedVectors(String resource, Kind kind, Version version)
      throws IOException {
    TestVectors.TestVector vector = firstSuccessful(resource);
    String auxiliary =
        switch (kind) {
          case LOCAL_WRAP -> vector.wrappingKey;
          case LOCAL_PW -> vector.password;
          case SEAL -> vector.sealingSecretKey;
          default -> null;
        };
    structuralMutations(vector.name, kind, version, vector.paserk, auxiliary, false);
    authenticationMutations(vector.name, kind, version, vector.paserk, auxiliary);
  }

  private static TestVectors.TestVector firstSuccessful(String resource) throws IOException {
    return TestVectors.paserk("test-vectors/" + resource).stream()
        .filter(vector -> !vector.expectFail)
        .findFirst()
        .orElseThrow(() -> new IllegalStateException("no successful vector in " + resource));
  }

  private static void structuralMutations(
      String vectorId, Kind kind, Version version, String paserk, String auxiliary,
      boolean rawKeyPayload) {
    String header = paserk.substring(0, paserk.lastIndexOf('.') + 1);
    String payload = paserk.substring(header.length());
    String versionPrefix = paserk.substring(0, paserk.indexOf('.'));
    String otherVersion = versionPrefix.equals("k3") ? "k4" : "k3";

    add(vectorId, "header version " + versionPrefix + "->" + otherVersion, MutationStage.HEADER,
        kind, version, otherVersion + paserk.substring(versionPrefix.length()), auxiliary);
    String otherType = kind == Kind.LOCAL ? "public" : "local";
    String typeLabel = header.substring(versionPrefix.length() + 1, header.length() - 1);
    add(vectorId, "header type " + typeLabel + "->" + otherType, MutationStage.HEADER, kind,
        version, versionPrefix + "." + otherType + "." + payload, auxiliary);
    add(vectorId, "header version uppercased", MutationStage.HEADER, kind, version,
        versionPrefix.toUpperCase(java.util.Locale.ROOT) + paserk.substring(versionPrefix.length()),
        auxiliary);

    add(vectorId, "payload segment emptied", MutationStage.STRUCTURE, kind, version, header,
        auxiliary);
    add(vectorId, "extra segment appended", MutationStage.STRUCTURE, kind, version,
        paserk + ".extra", auxiliary);

    add(vectorId, "payload padding '=' appended", MutationStage.ENCODING, kind, version,
        header + payload + "=", auxiliary);
    add(vectorId, "payload invalid character @0", MutationStage.ENCODING, kind, version,
        header + "!" + payload.substring(1), auxiliary);
    String alias = nonCanonicalAlias(payload);
    if (alias != null) {
      add(vectorId, "payload non-canonical trailing bits @" + (payload.length() - 1),
          MutationStage.ENCODING, kind, version, header + alias, auxiliary);
    }

    if (rawKeyPayload) {
      byte[] body = Base64.getUrlDecoder().decode(payload);
      byte[] truncated = java.util.Arrays.copyOf(body, body.length / 2);
      add(vectorId, "payload truncated to " + truncated.length + " bytes", MutationStage.LENGTH,
          kind, version, header + encode(truncated), auxiliary);
      byte[] extended = java.util.Arrays.copyOf(body, body.length + 1);
      add(vectorId, "payload extended +1 byte", MutationStage.LENGTH, kind, version,
          header + encode(extended), auxiliary);
    }
  }

  private static void authenticationMutations(
      String vectorId, Kind kind, Version version, String paserk, String auxiliary) {
    String header = paserk.substring(0, paserk.lastIndexOf('.') + 1);
    byte[] body = Base64.getUrlDecoder().decode(paserk.substring(header.length()));
    addBitFlip(vectorId, kind, version, paserk, auxiliary, header, body, 0);
    addBitFlip(vectorId, kind, version, paserk, auxiliary, header, body, body.length - 1);
  }

  private static void addBitFlip(
      String vectorId, Kind kind, Version version, String paserk, String auxiliary, String header,
      byte[] body, int byteOffset) {
    byte[] mutated = body.clone();
    mutated[byteOffset] ^= 0x01;
    add(vectorId, "payload bit-flip @byte " + byteOffset, MutationStage.AUTHENTICATION, kind,
        version, header + encode(mutated), auxiliary);
  }

  private static void add(
      String vectorId, String label, MutationStage stage, Kind kind, Version version,
      String paserk, String auxiliary) {
    MUTATIONS.add(new PaserkMutation(vectorId, label, stage, kind, version, paserk, auxiliary));
  }

  private static String nonCanonicalAlias(String payload) {
    char last = payload.charAt(payload.length() - 1);
    int index = ALPHABET.indexOf(last);
    for (int bit = 0; bit < 6; bit++) {
      char candidate = ALPHABET.charAt(index ^ (1 << bit));
      String mutated = payload.substring(0, payload.length() - 1) + candidate;
      byte[] decoded = Base64.getUrlDecoder().decode(mutated);
      if (!encode(decoded).equals(mutated)) {
        return mutated;
      }
    }
    return null;
  }

  private static String encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static Stream<Arguments> mutations() {
    return MUTATIONS.stream().map(mutation -> Arguments.of(mutation.display(), mutation));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("mutations")
  void mutationIsRejected(String display, PaserkMutation mutation) {
    assertThrows(
        PaserkException.class,
        () -> execute(mutation),
        () -> "mutation unexpectedly accepted: " + display);
  }

  private static void execute(PaserkMutation mutation) {
    String paserk = mutation.paserk();
    switch (mutation.kind()) {
      case LOCAL -> {
        if (mutation.version() == Version.V3) {
          org.paseto4j.paserk.version3.Paserk.decodeLocal(paserk);
        } else {
          org.paseto4j.paserk.version4.Paserk.decodeLocal(paserk);
        }
      }
      case PUBLIC -> {
        if (mutation.version() == Version.V3) {
          org.paseto4j.paserk.version3.Paserk.decodePublicKey(paserk);
        } else {
          org.paseto4j.paserk.version4.Paserk.decodePublicKey(paserk);
        }
      }
      case SECRET -> {
        if (mutation.version() == Version.V3) {
          org.paseto4j.paserk.version3.Paserk.decodeSecretKey(paserk);
        } else {
          org.paseto4j.paserk.version4.Paserk.decodeSecretKey(paserk);
        }
      }
      case LOCAL_WRAP -> {
        WrappingKey wrappingKey = WrappingKey.fromBytes(HexToBytes.hexToBytes(mutation.auxiliary()));
        if (mutation.version() == Version.V3) {
          org.paseto4j.paserk.version3.Paserk.unwrapLocal(paserk, wrappingKey);
        } else {
          org.paseto4j.paserk.version4.Paserk.unwrapLocal(paserk, wrappingKey);
        }
      }
      case LOCAL_PW -> {
        char[] password = mutation.auxiliary().toCharArray();
        if (mutation.version() == Version.V3) {
          org.paseto4j.paserk.version3.Paserk.unwrapLocalWithPassword(paserk, password);
        } else {
          org.paseto4j.paserk.version4.Paserk.unwrapLocalWithPassword(paserk, password);
        }
      }
      case SEAL -> {
        SealingSecretKey sealingKey = sealingSecretKey(mutation.version(), mutation.auxiliary());
        if (mutation.version() == Version.V3) {
          org.paseto4j.paserk.version3.Paserk.unseal(paserk, sealingKey);
        } else {
          org.paseto4j.paserk.version4.Paserk.unseal(paserk, sealingKey);
        }
      }
    }
  }

  private static SealingSecretKey sealingSecretKey(Version version, String encoded) {
    if (encoded.startsWith("-----BEGIN")) {
      String body = encoded.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
      try {
        ASN1Sequence sequence =
            ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(Base64.getDecoder().decode(body)));
        return SealingSecretKey.from(
            KeyEncoding.decodeV3Secret(
                ASN1OctetString.getInstance(sequence.getObjectAt(1)).getOctets()));
      } catch (IOException e) {
        throw new AssertionError("Unable to decode reference P-384 sealing key", e);
      }
    }
    byte[] raw = HexToBytes.hexToBytes(encoded);
    return version == Version.V3
        ? SealingSecretKey.from(KeyEncoding.decodeV3Secret(raw))
        : SealingSecretKey.from(KeyEncoding.decodeV4Secret(raw));
  }

  @Test
  void everyStageIsCovered() {
    Map<MutationStage, Long> coverage =
        MUTATIONS.stream()
            .collect(
                Collectors.groupingBy(
                    PaserkMutation::stage,
                    () -> new EnumMap<>(MutationStage.class),
                    Collectors.counting()));
    for (MutationStage stage :
        EnumSet.of(
            MutationStage.HEADER,
            MutationStage.STRUCTURE,
            MutationStage.ENCODING,
            MutationStage.LENGTH,
            MutationStage.AUTHENTICATION)) {
      assertTrue(
          coverage.getOrDefault(stage, 0L) > 0, "no mutation hits stage " + stage);
    }
    coverage.forEach(
        (stage, count) ->
            System.out.println("[paserk] stage " + stage + " covered by " + count + " mutations"));
  }
}
