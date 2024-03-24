package com.example.testsecurityjwt.config;

import com.example.testsecurityjwt.jwt.JWTFilter;
import com.example.testsecurityjwt.jwt.JWTUtil;
import com.example.testsecurityjwt.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // AuthenticationManager 를 반환받기위해 필요한 AuthenticationConfiguration 인스턴스 주입
    private final AuthenticationConfiguration authenticationConfiguration;

    private final JWTUtil jwtUtil;

    // AuthenticationManager 를 반환하는 메서드 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors((cors) -> cors
                        .configurationSource(new CorsConfigurationSource() {
                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                                CorsConfiguration corsConfiguration = new CorsConfiguration();

                                // 3000번대 포트 허용
                                corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                                // get post header 와 같은 메서드 모두 허용
                                corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
                                // 프론트에서 credentials 설정을 하면 true로 바꿔줘야한다.
                                corsConfiguration.setAllowCredentials(true);
                                // 허용할 헤더를 설정
                                corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
                                // 허용하는 시간
                                corsConfiguration.setMaxAge(3600L);
                                // 우리쪽에서 사용자 클라이언트 단으 헤더를 보내줄때 Authorization에 JWT를 넣어서 보내주기때문에 Authorization 헤더 허용
                                corsConfiguration.setExposedHeaders(Collections.singletonList("Authorization"));
                                // 이렇게 하면 LoginFilter같은 필터들이 cors 문제에서 해결되었다.
                                return corsConfiguration;
                            }
                        }));

        http
                .csrf((auth) -> auth.disable());

        //From 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());
        http.
                addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // UsernamePasswordAuthenticationFilter 기반으로 동작하는 formLogin으로 로그인하는 방식을 disable 했으므로
        // 직접 구현한 UsernamePasswordAuthenticationFilter를 상속받아 구현한 LoginFilter를
        // 원래 UsernamePasswordAuthenticationFilter가 위치한 자리에 위치시킨다.
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);
        //세션 설정
        // jwt를 활용하는 방식은 세션을 STATELESS 방식을 활용하기 때문에 반드시 해당 코드를 작성
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
