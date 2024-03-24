package com.example.testsecurityjwt.service;

import com.example.testsecurityjwt.dto.CustomUserDetails;
import com.example.testsecurityjwt.entity.User;
import com.example.testsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User findUser = userRepository.findByUsername(username);
        if (findUser != null) {
            return new CustomUserDetails(findUser);
        }
        return null;
    }

}
