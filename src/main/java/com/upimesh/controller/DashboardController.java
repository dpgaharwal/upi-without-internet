package com.upimesh.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Dashboard ka controller.
 *
 * <p>Sirf ek kaam karta hai — root URL {@code /} pe request aane par
 * {@code dashboard.html} Thymeleaf template serve karta hai.
 * Saari actual functionality REST endpoints se aati hai jo
 * {@link ApiController} mein hain.
 */
@Controller
public class DashboardController {

  /**
   * Root URL pe aane par dashboard dikhata hai.
   *
   * @return Thymeleaf template name {@code "dashboard"}
   */
  @GetMapping("/")
  public String home() {
    return "dashboard";
  }
}
