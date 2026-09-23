/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.security.SignatureException;

/**
 * A single deterministic mutation of a valid token together with the processing stage expected
 * to reject it. The {@link #display()} value identifies the source vector and the mutation
 * position; it never contains key material.
 */
public record TokenMutation(
    String vectorId,
    String label,
    MutationStage stage,
    Purpose purpose,
    String token,
    String footer,
    String implicitAssertion) {

  public String display() {
    return vectorId + " :: " + label;
  }

  /**
   * The exception category the library promises for the expected rejection stage: structural
   * rejections surface as {@link PasetoException}, a public-token authentication failure surfaces
   * as {@link SignatureException}.
   */
  public Class<? extends Exception> expectedException() {
    if (purpose == Purpose.PURPOSE_PUBLIC && stage == MutationStage.AUTHENTICATION) {
      return SignatureException.class;
    }
    return PasetoException.class;
  }
}
