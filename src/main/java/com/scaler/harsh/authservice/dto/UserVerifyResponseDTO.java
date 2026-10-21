package com.scaler.harsh.authservice.dto;

import lombok.Getter;
import lombok.Setter;

// Local mirror of only the fields Auth Service needs from User Service's response.
// Extra fields in the real response (name, address, phone) are ignored by Jackson's default config.
@Getter @Setter
public class UserVerifyResponseDTO {
    private Integer id;
    private String username;
    private String email;
}