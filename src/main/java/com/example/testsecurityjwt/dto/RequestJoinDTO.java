package com.example.testsecurityjwt.dto;

import com.example.testsecurityjwt.entity.User;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class RequestJoinDTO {

    private String username;

    private String password;

    @Builder
    public RequestJoinDTO(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public User toEntity(String password, String role) {
        return User.builder()
                .username(username)
                .password(password)
                .role(role)
                .build();
    }
}
