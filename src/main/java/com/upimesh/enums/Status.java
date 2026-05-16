package com.upimesh.enums;

/**
 * Transaction ka final result.
 *
 * <p>{@code SETTLED} matlab paisa successfully transfer ho gaya.
 * {@code REJECTED} matlab instruction valid thi lekin kuch gadbad thi —
 * ya to balance kam tha ya spend token invalid tha.
 */
public enum Status {

  /** Payment successfully settle ho gayi — paisa sender se receiver ko gaya. */
  SETTLED,

  /** Payment reject ho gayi — balance insufficient tha ya token invalid tha. */
  REJECTED
}
