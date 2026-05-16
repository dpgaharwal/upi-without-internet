package com.upimesh;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * UPI Offline Mesh ka main entry point.
 *
 * <p>Yeh application ek Spring Boot server hai jo offline UPI payments ko
 * process karta hai. Sender ka phone bina internet ke payment packet encrypt
 * karta hai, woh packet Bluetooth gossip ke zariye hop-by-hop travel karta hai,
 * aur jab koi bridge device internet pakad leta hai tab server pe upload hota hai.
 *
 * <p>Bas {@code mvn spring-boot:run} chalao aur {@code http://localhost:8080}
 * pe dashboard open karo — koi external dependency nahi, H2 in-memory DB use
 * hota hai.
 */
@SpringBootApplication
public class UpiWithoutInternetApplication {

  public static void main(String[] args) {
    SpringApplication.run(UpiWithoutInternetApplication.class, args);
  }

}
