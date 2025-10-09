package com.rabinchuk.authenticationservice.security;

import com.rabinchuk.authenticationservice.model.RoleType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtTokenProvider {

    private final SecretKey secretKey;

    private final long accessTokenExpiration;

    private final long refreshTokenExpiration;


    public JwtTokenProvider(@Value("${app.jwt.secret}") String jwtSecret,
                            @Value("${app.jwt.tokenExpiration}") long accessTokenExpiration,
                            @Value("${app.jwt.refreshTokenExpiration}") long refreshTokenExpiration) {
        this.secretKey = getSigningKey(jwtSecret);
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    public String generateAccessToken(AppUserDetails userDetails) {
        return generateToken(userDetails, accessTokenExpiration);
    }

    public String generateRefreshToken(AppUserDetails userDetails) {
        return generateToken(userDetails, refreshTokenExpiration);
    }

    private String generateToken(AppUserDetails userDetails, long tokenExpiration) {
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        Claims claims = Jwts.claims()
                .subject(userDetails.getUsername())
                .add("roles", roles)
                .build();

        return Jwts.builder()
                .claims(claims)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + tokenExpiration))
                .signWith(secretKey)
                .compact();
    }

    private SecretKey getSigningKey(String jwtSecret) {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public String getEmailFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Set<RoleType> getRolesFromToken(String token) {
        List<String> roles = getClaimFromToken(token, claims -> claims.get("roles", List.class));
        return roles.stream()
                .map(RoleType::valueOf)
                .collect(Collectors.toSet());
    }

    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claimsResolver.apply(claims);
    }

}
