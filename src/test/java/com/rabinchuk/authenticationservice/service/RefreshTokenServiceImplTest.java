package com.rabinchuk.authenticationservice.service;

import com.rabinchuk.authenticationservice.exception.RefreshTokenException;
import com.rabinchuk.authenticationservice.model.RefreshToken;
import com.rabinchuk.authenticationservice.model.RoleType;
import com.rabinchuk.authenticationservice.model.UserCredentials;
import com.rabinchuk.authenticationservice.repository.RefreshTokenRepository;
import com.rabinchuk.authenticationservice.repository.UserCredentialsRepository;
import com.rabinchuk.authenticationservice.security.JwtTokenProvider;
import com.rabinchuk.authenticationservice.service.impl.RefreshTokenServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class RefreshTokenServiceImplTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserCredentialsRepository userCredentialsRepository;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @InjectMocks
    private RefreshTokenServiceImpl refreshTokenService;

    private UserCredentials userCredentials;

    @BeforeEach
    public void setUp() {
        userCredentials = UserCredentials.builder()
                .id(1L)
                .email("test@example.com")
                .password("password")
                .roles(Set.of(RoleType.ROLE_USER))
                .build();

        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenExpiration", 1800000L);
    }

    @Test
    @DisplayName("Create refresh token should delete old and save new token")
    void whenCreateRefreshToken_ShouldDeleteOldAndSaveNewToken() {
        when(userCredentialsRepository.findByEmail("test@example.com")).thenReturn(Optional.of(userCredentials));
        when(jwtTokenProvider.generateRefreshToken(any())).thenReturn("new-refresh-token");
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        RefreshToken createdToken = refreshTokenService.createRefreshToken("test@example.com");

        verify(refreshTokenRepository, times(1)).deleteByUserCredentials(userCredentials);
        verify(refreshTokenRepository, times(1)).save(any(RefreshToken.class));
        assertThat(createdToken.getToken()).isEqualTo("new-refresh-token");
        assertThat(createdToken.getUserCredentials()).isEqualTo(userCredentials);
        assertThat(createdToken.getExpiryDate()).isAfter(Instant.now());
    }

    @Test
    @DisplayName("Verify token with valid token")
    void whenVerifyExpiration_WithValidToken_ShouldReturnToken() {
        RefreshToken token = RefreshToken.builder()
                .token("valid-token")
                .expiryDate(Instant.now().plusMillis(10000))
                .build();

        RefreshToken result = refreshTokenService.verifyExpiration(token);

        assertThat(result).isEqualTo(token);
        verify(refreshTokenRepository, never()).delete(any());
    }

    @Test
    @DisplayName("Verify token with invalid token")
    void whenVerifyExpiration_WithExpiredToken_ShouldThrowExceptionAndDeleteToken() {
        RefreshToken token = RefreshToken.builder()
                .token("expired-token")
                .expiryDate(Instant.now().minusMillis(10000))
                .build();

        assertThrows(RefreshTokenException.class, () -> {
            refreshTokenService.verifyExpiration(token);
        });

        verify(refreshTokenRepository, times(1)).delete(token);
    }

}
