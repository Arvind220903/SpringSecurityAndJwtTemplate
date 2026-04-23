package com.example.demo.jwt;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.service.MyUserDetailService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

	@Autowired
	private JwtService jwtService;

	@Autowired
	private ApplicationContext context;

	@SuppressWarnings("unused")
	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {

		// ── 1. Extract Bearer token from Authorization header ──────────────────
		String authHeader = request.getHeader("Authorization");
		String token = null;
		String username = null;

		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			token = authHeader.substring(7); // strip "Bearer "
			try {
				username = jwtService.extractUsername(token);
			} catch (Exception e) {
				// Invalid/expired token — proceed unauthenticated, Spring Security handles it
			}
		}

		// ── 2. Validate token and set authentication in SecurityContext ─────────
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			try {
				UserDetails userDetails = context
						.getBean(MyUserDetailService.class)
						.loadUserByUsername(username);

				if (jwtService.validateToken(token, userDetails)) {
					UsernamePasswordAuthenticationToken authToken =
							new UsernamePasswordAuthenticationToken(
									userDetails,
									null,
									userDetails.getAuthorities());

					authToken.setDetails(
							new WebAuthenticationDetailsSource().buildDetails(request));

					SecurityContextHolder.getContext().setAuthentication(authToken);
				}
			} catch (Exception e) {
				// User not found or token mismatch — proceed unauthenticated
				SecurityContextHolder.clearContext();
			}
		}

		// ── 3. Continue the filter chain ───────────────────────────────────────
		filterChain.doFilter(request, response);
	}
}
