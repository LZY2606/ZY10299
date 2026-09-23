/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/** Stage of token processing at which a mutated token is expected to be rejected. */
public enum MutationStage {
  HEADER,
  STRUCTURE,
  FOOTER,
  ENCODING,
  LENGTH,
  AUTHENTICATION
}
