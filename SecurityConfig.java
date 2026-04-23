package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.demo.jwt.JwtFilter;
import com.example.demo.service.MyUserDetailService;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

	@Autowired
	private MyUserDetailService ud;

	@Autowired
	private JwtFilter jwtFilter;

	@Bean
	public SecurityFilterChain secure(HttpSecurity http) throws Exception {
		return http
				.csrf(customizer -> customizer.disable())
				.cors(customizer -> customizer.configurationSource(corsConfigurationSource()))
				.authorizeHttpRequests(request -> request
						// Allow CORS preflight requests and public endpoints
						.requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
						.requestMatchers("/login", "/register").permitAll()
						.anyRequest().authenticated())
				// Stateless — no HTTP session, JWT handles auth
				.sessionManagement(session ->
						session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				// Register JwtFilter BEFORE the default username/password filter
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
	}

	@Bean
	public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource() {
		org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();
		config.addAllowedOrigin("http://localhost:4200");
		config.addAllowedMethod("*");
		config.addAllowedHeader("*");
		config.setAllowCredentials(false);
		org.springframework.web.cors.UrlBasedCorsConfigurationSource source =
				new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return source;
	}

	@Bean
	public BCryptPasswordEncoder bc() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationProvider auth() {
		DaoAuthenticationProvider dao = new DaoAuthenticationProvider(ud);
		dao.setPasswordEncoder(bc());
		return dao;
	}

	@Bean
	public AuthenticationManager authmange(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
}
