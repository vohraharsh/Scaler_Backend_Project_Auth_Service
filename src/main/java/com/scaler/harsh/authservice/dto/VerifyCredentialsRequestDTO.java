package com.scaler.harsh.authservice.dto;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class VerifyCredentialsRequestDTO {
    private String username;
    private String password;
}