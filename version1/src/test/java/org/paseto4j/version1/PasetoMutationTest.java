/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.paseto4j.commons.HexToBytes.hexToBytes;
import static org.paseto4j.version1.CryptoFunctions.convertBytesToRSAPrivateKey;
import static org.paseto4j.version1.CryptoFunctions.convertBytesToRSAPublicKey;

import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
import org.paseto4j.commons.TokenMutation;
import org.paseto4j.commons.TokenMutations;

/**
 * Deterministic mutation suite derived from the successful v1 local/public vectors. Every
 * mutation must be rejected at its expected stage with the exception category the library
 * promises; no mutation may return a partial token or plaintext. Display names carry the vector
 * id and mutation position, never key material.
 */
class PasetoMutationTest {

  private static final int NONCE_BYTES = 32;
  private static final int TAG_BYTES = 48;
  private static final int SIGNATURE_BYTES = 256;

  private static final String KEY =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  private static final String NONCE = "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2";

  private static final Map<String, SecretKey> LOCAL_KEYS = new HashMap<>();
  private static final Map<String, RSAPublicKey> PUBLIC_KEYS = new HashMap<>();
  private static final List<TokenMutation> LOCAL_MUTATIONS = new ArrayList<>();
  private static final List<TokenMutation> PUBLIC_MUTATIONS = new ArrayList<>();

  static {
    Security.addProvider(new BouncyCastleProvider());
    setUpLocal();
    setUpPublic();
  }

  private static void localVector(String id, String token, String footer) {
    SecretKey key = SecretKey.fromHexString(KEY);
    LOCAL_KEYS.put(id, key);
    LOCAL_MUTATIONS.addAll(
        TokenMutations.forLocalVector(id, token, footer, "", NONCE_BYTES, TAG_BYTES, false));
  }

  private static void setUpLocal() {
    String firstToken =
        "v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8";
    localVector("v1.local#1", firstToken, "");
    localVector(
        "v1.local#2",
        "v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkRGlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzkMr1RvfDI8emoPoW83q4Q60_xpHaw",
        "");
    localVector(
        "v1.local#3",
        "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHeJUYk4IK_JEdUeo_uFRqAIgHsiGCg",
        "");
    localVector(
        "v1.local#4",
        "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbHXUTWXchFEi0etJ4u6tqgxZSklcec",
        "");
    localVector(
        "v1.local#5",
        "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
        "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}");
    localVector(
        "v1.local#6",
        "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
        "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}");

    LOCAL_MUTATIONS.addAll(
        TokenMutations.lengthTable(
            "v1.local#1", Purpose.PURPOSE_LOCAL, firstToken, "", "", NONCE_BYTES + TAG_BYTES));

    SecretKey key = SecretKey.fromHexString(KEY);
    String unicodeToken =
        PasetoLocal.encrypt(key, hexToBytes(NONCE), "こんにちは 🌍 é", "fötter-フッター");
    LOCAL_KEYS.put("v1.local-unicode", key);
    LOCAL_MUTATIONS.addAll(
        TokenMutations.forLocalVector(
            "v1.local-unicode", unicodeToken, "fötter-フッター", "", NONCE_BYTES, TAG_BYTES,
            false));

    String minimalToken = PasetoLocal.encrypt(key, hexToBytes(NONCE), "", "");
    LOCAL_KEYS.put("v1.local-minimal", key);
    LOCAL_MUTATIONS.addAll(
        TokenMutations.forLocalVector(
            "v1.local-minimal", minimalToken, "", "", NONCE_BYTES, TAG_BYTES, false));
  }

  private static String publicVector(String id, String payload, String footer) {
    RSAPrivateKey privateKey =
        convertBytesToRSAPrivateKey(hexToBytes(PasetoPublicTest.PRIVATE_KEY));
    String token = Paseto.sign(privateKey, payload, footer);
    PUBLIC_KEYS.put(
        id, convertBytesToRSAPublicKey(hexToBytes(PasetoPublicTest.PUBLIC_KEY)));
    PUBLIC_MUTATIONS.addAll(
        TokenMutations.forPublicVector(id, token, footer, "", SIGNATURE_BYTES, false));
    return token;
  }

  private static void setUpPublic() {
    String firstToken =
        publicVector(
            "v1.public#1",
            "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}", "");
    publicVector(
        "v1.public#2",
        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}");
    publicVector("v1.public-unicode", "こんにちは 🌍 é", "fötter-フッター");
    publicVector("v1.public-minimal", "", "");

    PUBLIC_MUTATIONS.addAll(
        TokenMutations.lengthTable(
            "v1.public#1", Purpose.PURPOSE_PUBLIC, firstToken, "", "", SIGNATURE_BYTES));
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
        () -> Paseto.decrypt(key, mutation.token(), mutation.footer()),
        () -> "mutation unexpectedly accepted: " + display);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("publicMutations")
  void publicMutationIsRejected(String display, TokenMutation mutation) {
    RSAPublicKey key = PUBLIC_KEYS.get(mutation.vectorId());
    assertThrows(
        mutation.expectedException(),
        () -> Paseto.parse(key, mutation.token(), mutation.footer()),
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
            System.out.println("[v1] stage " + stage + " covered by " + count + " mutations"));
  }
}
