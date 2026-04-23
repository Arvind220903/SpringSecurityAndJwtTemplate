package com.example.demo.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	// Fixed key from application.properties — same across every startup
	@Value("${jwt.secret}")
	private String secretKey;

	// ─── Generate Token ───────────────────────────────────────────────────────

	public String generateKey(String email) {
		Map<String, Object> claims = new HashMap<>();
		return Jwts.builder()
				.claims()
				.add(claims)
				.subject(email)
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 10)) // 10 hours
				.and()
				.signWith(getKey())
				.compact();
	}

	// ─── Signing Key ─────────────────────────────────────────────────────────

	private Key getKey() {
		byte[] keyBytes = Decoders.BASE64.decode(secretKey);
		return Keys.hmacShaKeyFor(keyBytes);
	}

	// ─── Extract Claims ───────────────────────────────────────────────────────

	private Claims extractAllClaims(String token) {
		return Jwts.parser()
				.verifyWith((SecretKey) getKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
		return claimResolver.apply(extractAllClaims(token));
	}

	// ─── Extract Username (email) ─────────────────────────────────────────────

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	// ─── Validate Token ───────────────────────────────────────────────────────

	public boolean isTokenExpired(String token) {
		return extractClaim(token, Claims::getExpiration).before(new Date());
	}

	public boolean validateToken(String token, UserDetails userDetails) {
		String username = extractUsername(token);
		return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
	}
}
