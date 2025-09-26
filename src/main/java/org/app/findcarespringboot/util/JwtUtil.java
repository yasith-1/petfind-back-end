package org.app.findcarespringboot.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil { // Helper class for JWT operations

    private final String SECRET_KEY;  // final field

    public JwtUtil(@Value("${jwt.secret}") String secret) {  // <— constructor parameter annotated
        this.SECRET_KEY = secret;
    }

    public String generateToken(String username, long expirationMillis) {
        return Jwts.builder()
                .setSubject(username) // who this token belongs to
                .setIssuedAt(new Date()) // when it was created
                .setExpiration(new Date(System.currentTimeMillis() + expirationMillis)) // expiry time
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // signature
                .compact(); // final token string
    }

    public String extractUsername(String token) { // Read username from token
        return Jwts.parser() // Start parsing
                .setSigningKey(SECRET_KEY) // Use our secret to verify
                .parseClaimsJws(token) // Parse claims
                .getBody() // Get token body
                .getSubject(); // Extract username
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false; // token invalid or expired
        }
    }

}