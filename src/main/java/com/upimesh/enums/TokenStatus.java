package com.upimesh.enums;

/**
 * Offline spend token ki lifecycle states.
 *
 * <p>Token issue hone ke baad {@code ACTIVE} hota hai. Jab payment settle
 * hoti hai to {@code CONSUMED} ho jata hai. Agar time limit cross ho jaye
 * bina use ke to {@code EXPIRED} ho jata hai. Dono {@code CONSUMED} aur
 * {@code EXPIRED} terminal states hain — wapas {@code ACTIVE} nahi ho sakte.
 */
public enum TokenStatus {

  /** Token abhi valid hai, use nahi hua. Payment ke liye use kiya ja sakta hai. */
  ACTIVE,

  /** Token ek baar payment settle karne mein use ho gaya. Dobara use nahi ho sakta. */
  CONSUMED,

  /** Token ki time limit khatam ho gayi bina use ke. */
  EXPIRED
}