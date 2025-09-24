package com.rabinchuk.authenticationservice.service;

import com.rabinchuk.authenticationservice.dto.CreateAdminRequest;
import com.rabinchuk.authenticationservice.dto.JwtAuthenticationResponse;
import com.rabinchuk.authenticationservice.dto.RefreshTokenRequest;
import com.rabinchuk.authenticationservice.dto.SignInRequest;
import com.rabinchuk.authenticationservice.dto.SignUpRequest;
import com.rabinchuk.authenticationservice.dto.UserInfo;
import com.rabinchuk.authenticationservice.dto.ValidateTokenRequest;
import com.rabinchuk.authenticationservice.exception.RefreshTokenException;
import com.rabinchuk.authenticationservice.exception.UserAlreadyExistsException;
import com.rabinchuk.authenticationservice.model.RefreshToken;
import com.rabinchuk.authenticationservice.model.RoleType;
import com.rabinchuk.authenticationservice.model.UserCredentials;
import com.rabinchuk.authenticationservice.repository.UserCredentialsRepository;
import com.rabinchuk.authenticationservice.security.AppUserDetails;
import com.rabinchuk.authenticationservice.security.JwtTokenProvider;
import com.rabinchuk.authenticationservice.service.impl.AuthenticationServiceImpl;
import com.rabinchuk.authenticationservice.service.impl.RefreshTokenServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

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
public class AuthenticationServiceImplTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private UserCredentialsRepository userCredentialsRepository;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private RefreshTokenServiceImpl refreshTokenServiceImpl;

    @InjectMocks
    private AuthenticationServiceImpl authenticationService;

    private UserCredentials userCredentials;
    private AppUserDetails appUserDetails;

    @BeforeEach
    public void setUp() {
        userCredentials = UserCredentials.builder()
                .id(1L)
                .email("test@example.com")
                .password("password")
                .roles(Set.of(RoleType.ROLE_USER))
                .build();
        appUserDetails = new AppUserDetails(userCredentials);
    }

    @Test
    @DisplayName("Sign in with valid credentials")
    void whenSignIn_WithValidCredentials_ShouldReturnTokens() {
        SignInRequest signInRequest = new SignInRequest("test@example.com", "password");
        RefreshToken refreshToken = RefreshToken.builder().token("refreshToken").build();

        when(userCredentialsRepository.findByEmail(signInRequest.email())).thenReturn(Optional.of(userCredentials));
        when(jwtTokenProvider.generateAccessToken(any(AppUserDetails.class))).thenReturn("accessToken");
        when(refreshTokenServiceImpl.createRefreshToken(signInRequest.email())).thenReturn(refreshToken);

        JwtAuthenticationResponse response = authenticationService.signIn(signInRequest);

        assertThat(response.accessToken()).isEqualTo("accessToken");
        assertThat(response.refreshToken()).isEqualTo("refreshToken");
        verify(authenticationManager, times(1)).authenticate(any());
    }

    @Test
    @DisplayName("Sign in with invalid credentials")
    void whenSignIn_WithInvalidCredentials_ShouldThrowBadCredentialsException() {
        SignInRequest signInRequest = new SignInRequest("test@example.com", "wrongpassword");
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Invalid credentials"));

        assertThrows(BadCredentialsException.class, () -> {
            authenticationService.signIn(signInRequest);
        });
    }

    @Test
    @DisplayName("Sign up with valid email")
    void whenSignUp_WithNewEmail_ShouldSaveUser() {
        SignUpRequest signUpRequest = new SignUpRequest("newuser@example.com", "password123");
        when(userCredentialsRepository.findByEmail(signUpRequest.email())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(signUpRequest.password())).thenReturn("encodedPassword123");

        authenticationService.signUp(signUpRequest);

        verify(userCredentialsRepository, times(1)).save(any(UserCredentials.class));
    }

    @Test
    @DisplayName("Sign up with invalid email")
    void whenSignUp_WithExistingEmail_ShouldThrowUserAlreadyExistsException() {
        SignUpRequest signUpRequest = new SignUpRequest("test@example.com", "password123");
        when(userCredentialsRepository.findByEmail(signUpRequest.email())).thenReturn(Optional.of(userCredentials));

        assertThrows(UserAlreadyExistsException.class, () -> {
            authenticationService.signUp(signUpRequest);
        });
        verify(userCredentialsRepository, never()).save(any());
    }

    @Test
    @DisplayName("Refresh token with valid token")
    void whenRefreshToken_WithValidToken_ShouldReturnNewAccessToken() {
        RefreshTokenRequest request = new RefreshTokenRequest("validRefreshToken");
        RefreshToken refreshToken = RefreshToken.builder()
                .token("validRefreshToken")
                .userCredentials(userCredentials)
                .build();

        when(refreshTokenServiceImpl.findByToken("validRefreshToken")).thenReturn(Optional.of(refreshToken));
        when(refreshTokenServiceImpl.verifyExpiration(refreshToken)).thenReturn(refreshToken);
        when(jwtTokenProvider.generateAccessToken(any(AppUserDetails.class))).thenReturn("newAccessToken");

        JwtAuthenticationResponse response = authenticationService.refreshToken(request);

        assertThat(response.accessToken()).isEqualTo("newAccessToken");
        assertThat(response.refreshToken()).isEqualTo("validRefreshToken");
    }

    @Test
    @DisplayName("Refresh token with invalid token")
    void whenRefreshToken_WithInvalidToken_ShouldThrowException() {
        RefreshTokenRequest request = new RefreshTokenRequest("invalidRefreshToken");
        when(refreshTokenServiceImpl.findByToken("invalidRefreshToken")).thenReturn(Optional.empty());

        assertThrows(RefreshTokenException.class, () -> {
            authenticationService.refreshToken(request);
        });
    }

    @Test
    @DisplayName("Validate token with valid token")
    void whenValidateToken_WithValidToken_ShouldReturnUserInfo() {
        ValidateTokenRequest request = new ValidateTokenRequest("validToken");
        when(jwtTokenProvider.validateToken("validToken")).thenReturn(true);
        when(jwtTokenProvider.getEmailFromToken("validToken")).thenReturn("test@example.com");
        when(jwtTokenProvider.getRolesFromToken("validToken")).thenReturn(Set.of(RoleType.ROLE_USER));

        UserInfo userInfo = authenticationService.validateToken(request);

        assertThat(userInfo.email()).isEqualTo("test@example.com");
        assertThat(userInfo.roles()).isEqualTo(Set.of(RoleType.ROLE_USER));
    }

    @Test
    @DisplayName("Validate token with invalid token")
    void whenValidateToken_WithInvalidToken_ShouldThrowException() {
        ValidateTokenRequest request = new ValidateTokenRequest("invalidToken");
        when(jwtTokenProvider.validateToken("invalidToken")).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> {
            authenticationService.validateToken(request);
        });
    }

    @Test
    @DisplayName("Create admin with valid email")
    void whenCreateAdmin_WithNewEmail_ShouldSaveAdminUser() {
        CreateAdminRequest request = new CreateAdminRequest("admin@example.com", "adminpass");
        when(userCredentialsRepository.findByEmail(request.email())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(request.password())).thenReturn("encodedAdminPass");

        ArgumentCaptor<UserCredentials> userCaptor = ArgumentCaptor.forClass(UserCredentials.class);

        authenticationService.createAdmin(request);

        verify(userCredentialsRepository, times(1)).save(userCaptor.capture());
        UserCredentials savedUser = userCaptor.getValue();
        assertThat(savedUser.getEmail()).isEqualTo("admin@example.com");
        assertThat(savedUser.getPassword()).isEqualTo("encodedAdminPass");
        assertThat(savedUser.getRoles()).isEqualTo(Set.of(RoleType.ROLE_ADMIN));
    }

    @Test
    @DisplayName("Create admin with invalid email")
    void whenCreateAdmin_WithExistingEmail_ShouldThrowException() {
        CreateAdminRequest request = new CreateAdminRequest("admin@example.com", "adminpass");
        when(userCredentialsRepository.findByEmail(request.email())).thenReturn(Optional.of(new UserCredentials()));

        assertThrows(UserAlreadyExistsException.class, () -> {
            authenticationService.createAdmin(request);
        });
        verify(userCredentialsRepository, never()).save(any());
    }

}
