package com.example.testsecurityjwt.service;


import com.example.testsecurityjwt.dto.RequestJoinDTO;
import com.example.testsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(RequestJoinDTO joinDTO) {

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        boolean isAlreadyExists = userRepository.existsByUsername(username);
        if (isAlreadyExists) {
            return;
        }

        userRepository.save(
                joinDTO.toEntity(
                        bCryptPasswordEncoder.encode(password),
                        "ROLE_ADMIN")
        );



    }
}
