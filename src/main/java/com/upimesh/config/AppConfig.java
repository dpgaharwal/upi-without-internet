package com.upimesh.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Application-level configuration class.
 *
 * <p>Abhi sirf {@code @EnableScheduling} enable karta hai jisse
 * {@code @Scheduled} methods (jaise idempotency cache eviction aur
 * spend token expiry) background mein automatically chalte rahein.
 */
@Configuration
@EnableScheduling
public class AppConfig {}
