package com.upimesh.enums;

public enum TokenStatus {
    /** Token is valid and has not been used yet. */
    ACTIVE,

    /** Token was successfully used to settle a payment. Terminal state. */
    CONSUMED,

    /** Token passed its expiresAt without being used. Terminal state. */
    EXPIRED
}