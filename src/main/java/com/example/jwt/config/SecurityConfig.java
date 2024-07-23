package com.example.jwt.config;

import com.example.jwt.jwt.JwtFilter;
import com.example.jwt.jwt.JwtUtil;
import com.example.jwt.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	//AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
	private final AuthenticationConfiguration authenticationConfiguration;
	private final JwtUtil jwtUtil;

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	//AuthenticationManager Bean 등록
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		//csrf disable
		http
			.csrf(AbstractHttpConfigurer::disable);

		//From 로그인 방식 disable
		http
			.formLogin(AbstractHttpConfigurer::disable);

		//http basic 인증 방식 disable
		http
			.httpBasic(AbstractHttpConfigurer::disable);

		//경로별 인가 작업
		http
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/login", "/", "/join").permitAll()
				.requestMatchers("/admin").hasRole("USER")
				.anyRequest().authenticated());

		http
			.addFilterBefore(new JwtFilter(jwtUtil), LoginFilter.class);


		//필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
		http
			.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);


		//세션 설정
		http
			.sessionManagement(session -> session
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		http
			.cors(cors -> cors.configurationSource(getCorsConfiguration()));

		return http.build();
	}

	CorsConfigurationSource getCorsConfiguration() {

		CorsConfiguration configuration = new CorsConfiguration();

		configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
		configuration.setAllowedMethods(Collections.singletonList("*"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(Collections.singletonList("*"));
		configuration.setMaxAge(3600L);

		configuration.setExposedHeaders(Collections.singletonList("Authorization"));


		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}