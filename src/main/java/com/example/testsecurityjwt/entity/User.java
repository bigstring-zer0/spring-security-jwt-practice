package com.example.testsecurityjwt.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String username;

    private String password;

    private String Role;

    @Builder
    public User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.Role = role;
    }
}
