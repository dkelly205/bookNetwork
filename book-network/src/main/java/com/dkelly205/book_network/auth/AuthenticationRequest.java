package com.dkelly205.book_network.auth;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AuthenticationRequest(
        @Email(message = "Email is not in valid format")
        @NotBlank(message="Email is required")
        String email,
        @NotBlank(message="Password is required")
        @Size(min = 8, message = "Password must be between 8 - 20 characters long")
        @Size(max = 20, message = "Password must be between 8 - 20 characters long")
        String password) {
}
