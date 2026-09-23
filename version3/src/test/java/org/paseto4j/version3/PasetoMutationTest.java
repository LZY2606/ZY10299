/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.paseto4j.commons.HexToBytes.hexToBytes;

import java.io.IOException;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.paseto4j.commons.MutationStage;
import org.paseto4j.commons.Purpose;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TestVectors;
import org.paseto4j.commons.TokenMutation;
import org.paseto4j.commons.TokenMutations;

/**
 * Deterministic mutation suite derived from the successful v3 local/public vectors. Every
 * mutation must be rejected at its expected stage with the exception category the library
 * promises; no mutation may return a partial token or plaintext. Display names carry the vector
 * id and mutation position, never key material.
 */
class PasetoMutationTest {

  private static final int NONCE_BYTES = 32;
  private static final int TAG_BYTES = 48;
  private static final int SIGNATURE_BYTES = 96;

  private static final Map<String, SecretKey> LOCAL_KEYS = new HashMap<>();
  private static final Map<String, ECPublicKey> PUBLIC_KEYS = new HashMap<>();
  private static final List<TokenMutation> LOCAL_MUTATIONS = new ArrayList<>();
  private static final List<TokenMutation> PUBLIC_MUTATIONS = new ArrayList<>();

  static {
    Security.addProvider(new BouncyCastleProvider());
    try {
      setUpLocal();
      setUpPublic();
    } catch (IOException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  private static void setUpLocal() throws IOException {
    List<TestVectors.TestVector> vectors =
        TestVectors.v3(Purpose.PURPOSE_LOCAL).stream()
            .filter(vector -> !vector.expectFail)
            .toList();
    for (TestVectors.TestVector vector : vectors) {
      LOCAL_KEYS.put(vector.name, SecretKey.fromHexString(vector.key));
      LOCAL_MUTATIONS.addAll(
          TokenMutations.forLocalVector(
              vector.name, vector.token, vector.footer, vector.implicitAssertion,
              NONCE_BYTES, TAG_BYTES, true));
    }
    TestVectors.TestVector first = vectors.get(0);
    LOCAL_MUTATIONS.addAll(
        TokenMutations.lengthTable(
            first.name, Purpose.PURPOSE_LOCAL, first.token, first.footer,
            first.implicitAssertion, NONCE_BYTES + TAG_BYTES));

    SecretKey key = LOCAL_KEYS.get(first.name);
    byte[] nonce = hexToBytes(first.nonce);
    String unicodeToken =
        PasetoLocal.encrypt(key, nonce, "こんにちは 🌍 é", "fötter-フッター", "アサーション");
    LOCAL_KEYS.put("v3.local-unicode", key);
    LOCAL_MUTATIONS.addAll(
        TokenMutations.forLocalVector(
            "v3.local-unicode", unicodeToken, "fötter-フッター", "アサーション",
            NONCE_BYTES, TAG_BYTES, true));

    String minimalToken = PasetoLocal.encrypt(key, nonce, "", "", "");
    LOCAL_KEYS.put("v3.local-minimal", key);
    LOCAL_MUTATIONS.addAll(
        TokenMutations.forLocalVector(
            "v3.local-minimal", minimalToken, "", "", NONCE_BYTES, TAG_BYTES, true));
  }

  private static void setUpPublic() throws IOException {
    List<TestVectors.TestVector> vectors =
        TestVectors.v3(Purpose.PURPOSE_PUBLIC).stream()
            .filter(vector -> !vector.expectFail)
            .toList();
    for (TestVectors.TestVector vector : vectors) {
      PUBLIC_KEYS.put(
          vector.name, (ECPublicKey) PasetoPublicTest.readEC(vector.secretKeyPem).getPublic());
      PUBLIC_MUTATIONS.addAll(
          TokenMutations.forPublicVector(
              vector.name, vector.token, vector.footer, vector.implicitAssertion,
              SIGNATURE_BYTES, true));
    }
    TestVectors.TestVector first = vectors.get(0);
    PUBLIC_MUTATIONS.addAll(
        TokenMutations.lengthTable(
            first.name, Purpose.PURPOSE_PUBLIC, first.token, first.footer,
            first.implicitAssertion, SIGNATURE_BYTES));

    var keyPair = PasetoPublicTest.readEC(first.secretKeyPem);
    ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
    String unicodeToken = Paseto.sign(privateKey, "こんにちは 🌍 é", "fötter-フッター", "アサーション");
    PUBLIC_KEYS.put("v3.public-unicode", (ECPublicKey) keyPair.getPublic());
    PUBLIC_MUTATIONS.addAll(
        TokenMutations.forPublicVector(
            "v3.public-unicode", unicodeToken, "fötter-フッター", "アサーション",
            SIGNATURE_BYTES, true));

    String minimalToken = Paseto.sign(privateKey, "", "", "");
    PUBLIC_KEYS.put("v3.public-minimal", (ECPublicKey) keyPair.getPublic());
    PUBLIC_MUTATIONS.addAll(
        TokenMutations.forPublicVector(
            "v3.public-minimal", minimalToken, "", "", SIGNATURE_BYTES, true));
  }

  private static Stream<Arguments> localMutations() {
    return LOCAL_MUTATIONS.stream().map(mutation -> Arguments.of(mutation.display(), mutation));
  }

  private static Stream<Arguments> publicMutations() {
    return PUBLIC_MUTATIONS.stream().map(mutation -> Arguments.of(mutation.display(), mutation));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("localMutations")
  void localMutationIsRejected(String display, TokenMutation mutation) {
    SecretKey key = LOCAL_KEYS.get(mutation.vectorId());
    assertThrows(
        mutation.expectedException(),
        () ->
            Paseto.decrypt(
                key, mutation.token(), mutation.footer(), mutation.implicitAssertion()),
        () -> "mutation unexpectedly accepted: " + display);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("publicMutations")
  void publicMutationIsRejected(String display, TokenMutation mutation) {
    ECPublicKey key = PUBLIC_KEYS.get(mutation.vectorId());
    assertThrows(
        mutation.expectedException(),
        () -> Paseto.parse(key, mutation.token(), mutation.footer(), mutation.implicitAssertion()),
        () -> "mutation unexpectedly accepted: " + display);
  }

  @Test
  void everyStageIsCovered() {
    List<TokenMutation> all = new ArrayList<>(LOCAL_MUTATIONS);
    all.addAll(PUBLIC_MUTATIONS);
    Map<MutationStage, Long> coverage = TokenMutations.coverage(all);
    for (MutationStage stage : MutationStage.values()) {
      assertTrue(
          coverage.getOrDefault(stage, 0L) > 0, "no mutation hits stage " + stage);
    }
    coverage.forEach(
        (stage, count) ->
            System.out.println("[v3] stage " + stage + " covered by " + count + " mutations"));
  }
}
