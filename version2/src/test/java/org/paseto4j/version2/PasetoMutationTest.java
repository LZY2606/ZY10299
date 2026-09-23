/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.paseto4j.commons.HexToBytes.hexToBytes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
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
 * Deterministic mutation suite derived from the successful v2 local/public vectors. Every
 * mutation must be rejected at its expected stage with the exception category the library
 * promises; no mutation may return a partial token or plaintext. Display names carry the vector
 * id and mutation position, never key material.
 */
class PasetoMutationTest {

  private static final int NONCE_BYTES = 24;
  private static final int TAG_BYTES = 16;
  private static final int SIGNATURE_BYTES = 64;

  private static final String KEY =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  private static final String NONCE = "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b";
  private static final String PUBLIC_KEY =
      "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
  private static final String PRIVATE_KEY =
      "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";

  private static final Map<String, SecretKey> LOCAL_KEYS = new HashMap<>();
  private static final Map<String, PublicKey> PUBLIC_KEYS = new HashMap<>();
  private static final List<TokenMutation> LOCAL_MUTATIONS = new ArrayList<>();
  private static final List<TokenMutation> PUBLIC_MUTATIONS = new ArrayList<>();

  static {
    setUpLocal();
    setUpPublic();
  }

  private static void localVector(String id, String token, String footer) {
    LOCAL_KEYS.put(id, SecretKey.fromHexString(KEY));
    LOCAL_MUTATIONS.addAll(
        TokenMutations.forLocalVector(id, token, footer, "", NONCE_BYTES, TAG_BYTES, false));
  }

  private static void setUpLocal() {
    String firstToken =
        "v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w";
    localVector("v2.local#1", firstToken, "");
    localVector(
        "v2.local#2",
        "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ",
        "");
    localVector(
        "v2.local#3",
        "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA",
        "");
    localVector(
        "v2.local#4",
        "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ",
        "");
    localVector(
        "v2.local#5",
        "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}");
    localVector(
        "v2.local#6",
        "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}");

    LOCAL_MUTATIONS.addAll(
        TokenMutations.lengthTable(
            "v2.local#1", Purpose.PURPOSE_LOCAL, firstToken, "", "", NONCE_BYTES + TAG_BYTES));

    SecretKey key = SecretKey.fromHexString(KEY);
    String unicodeToken =
        PasetoLocal.encrypt(key, hexToBytes(NONCE), "こんにちは 🌍 é", "fötter-フッター");
    LOCAL_KEYS.put("v2.local-unicode", key);
    LOCAL_MUTATIONS.addAll(
        TokenMutations.forLocalVector(
            "v2.local-unicode", unicodeToken, "fötter-フッター", "", NONCE_BYTES, TAG_BYTES,
            false));

    String minimalToken = PasetoLocal.encrypt(key, hexToBytes(NONCE), "", "");
    LOCAL_KEYS.put("v2.local-minimal", key);
    LOCAL_MUTATIONS.addAll(
        TokenMutations.forLocalVector(
            "v2.local-minimal", minimalToken, "", "", NONCE_BYTES, TAG_BYTES, false));
  }

  private static void publicVector(String id, String token, String footer) {
    PUBLIC_KEYS.put(id, PublicKey.fromHexString(PUBLIC_KEY));
    PUBLIC_MUTATIONS.addAll(
        TokenMutations.forPublicVector(id, token, footer, "", SIGNATURE_BYTES, false));
  }

  private static void setUpPublic() {
    String firstToken =
        "v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA";
    publicVector("v2.public#1", firstToken, "");
    publicVector(
        "v2.public#2",
        "v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz",
        "Cuon Alpinus");
    publicVector(
        "v2.public#3",
        "v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM",
        "");
    publicVector(
        "v2.public#4",
        "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz",
        "Cuon Alpinus");
    publicVector(
        "v2.public#5",
        "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI",
        "");
    publicVector(
        "v2.public#6",
        "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz",
        "Paragon Initiative Enterprises");

    PUBLIC_MUTATIONS.addAll(
        TokenMutations.lengthTable(
            "v2.public#1", Purpose.PURPOSE_PUBLIC, firstToken, "", "", SIGNATURE_BYTES));

    PrivateKey privateKey = PrivateKey.fromBytes(hexToBytes(PRIVATE_KEY));
    String unicodeToken = Paseto.sign(privateKey, "こんにちは 🌍 é", "fötter-フッター");
    publicVector("v2.public-unicode", unicodeToken, "fötter-フッター");
    String minimalToken = Paseto.sign(privateKey, "", "");
    publicVector("v2.public-minimal", minimalToken, "");
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
    PublicKey key = PUBLIC_KEYS.get(mutation.vectorId());
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
            System.out.println("[v2] stage " + stage + " covered by " + count + " mutations"));
  }
}
