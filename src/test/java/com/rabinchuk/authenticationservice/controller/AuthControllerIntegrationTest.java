package com.rabinchuk.authenticationservice.controller;

import com.rabinchuk.authenticationservice.dto.CreateAdminRequest;
import com.rabinchuk.authenticationservice.dto.JwtAuthenticationResponse;
import com.rabinchuk.authenticationservice.dto.RefreshTokenRequest;
import com.rabinchuk.authenticationservice.dto.SignInRequest;
import com.rabinchuk.authenticationservice.dto.SignUpRequest;
import com.rabinchuk.authenticationservice.dto.UserInfo;
import com.rabinchuk.authenticationservice.dto.ValidateTokenRequest;
import com.rabinchuk.authenticationservice.model.UserCredentials;
import com.rabinchuk.authenticationservice.repository.RefreshTokenRepository;
import com.rabinchuk.authenticationservice.repository.UserCredentialsRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Optional;

import static java.lang.Thread.sleep;
import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public class AuthControllerIntegrationTest {

    @Container
    @ServiceConnection
    private static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17");

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserCredentialsRepository userCredentialsRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @AfterEach
    void tearDown() {
        refreshTokenRepository.deleteAll();
        userCredentialsRepository.deleteAll();
    }

    @Test
    @DisplayName("Sign up successful")
    public void signUp_whenValidRequest_shouldCreateUserAndReturn201() {
        SignUpRequest request = new SignUpRequest("testuser@example.com", "password123");

        ResponseEntity<Void> response = restTemplate.postForEntity("/api/auth/signUp", request, Void.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(userCredentialsRepository.findByEmail("testuser@example.com")).isPresent();
    }

    @Test
    @DisplayName("Sign up with invalid email")
    public void signUp_whenEmailAlreadyExists_shouldReturn409() {
        SignUpRequest initialRequest = new SignUpRequest("existinguser@example.com", "password123");
        restTemplate.postForEntity("/api/auth/signUp", initialRequest, Void.class);

        SignUpRequest duplicateRequest = new SignUpRequest("existinguser@example.com", "anotherPassword");

        ResponseEntity<Object> response = restTemplate.postForEntity("/api/auth/signUp", duplicateRequest, Object.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    @DisplayName("Sign in successful")
    public void signIn_whenCredentialsAreValid_shouldReturnTokensAnd200() {
        SignUpRequest signUpRequest = new SignUpRequest("signinuser@example.com", "password123");
        restTemplate.postForEntity("/api/auth/signUp", signUpRequest, Void.class);

        SignInRequest signInRequest = new SignInRequest("signinuser@example.com", "password123");

        ResponseEntity<JwtAuthenticationResponse> response = restTemplate.postForEntity("/api/auth/signIn", signInRequest, JwtAuthenticationResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().accessToken()).isNotBlank();
        assertThat(response.getBody().refreshToken()).isNotBlank();
    }

    @Test
    @DisplayName("Sign in with invalid password")
    public void signIn_whenPasswordIsInvalid_shouldReturn401() {
        SignUpRequest signUpRequest = new SignUpRequest("badpass@example.com", "password123");
        restTemplate.postForEntity("/api/auth/signUp", signUpRequest, Void.class);

        SignInRequest signInRequest = new SignInRequest("badpass@example.com", "wrong-password");

        ResponseEntity<Object> response = restTemplate.postForEntity("/api/auth/signIn", signInRequest, Object.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Refresh token successful")
    public void refreshToken_whenTokenIsValid_shouldReturnNewAccessToken() throws InterruptedException {
        SignUpRequest signUpRequest = new SignUpRequest("refreshuser@example.com", "password123");
        restTemplate.postForEntity("/api/auth/signUp", signUpRequest, Void.class);

        SignInRequest signInRequest = new SignInRequest("refreshuser@example.com", "password123");
        ResponseEntity<JwtAuthenticationResponse> signInResponse = restTemplate.postForEntity("/api/auth/signIn", signInRequest, JwtAuthenticationResponse.class);
        String refreshToken = signInResponse.getBody().refreshToken();
        String oldAccessToken = signInResponse.getBody().accessToken();

        sleep(1000);

        RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshToken);

        ResponseEntity<JwtAuthenticationResponse> refreshResponse = restTemplate.postForEntity("/api/auth/refresh", refreshRequest, JwtAuthenticationResponse.class);

        assertThat(refreshResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshResponse.getBody()).isNotNull();
        assertThat(refreshResponse.getBody().refreshToken()).isEqualTo(refreshToken);
        assertThat(refreshResponse.getBody().accessToken()).isNotBlank().isNotEqualTo(oldAccessToken);
    }

    @Test
    @DisplayName("Validate token successful")
    public void validateToken_whenTokenIsValid_shouldReturnUserInfoAnd200() {
        SignUpRequest signUpRequest = new SignUpRequest("validateuser@example.com", "password123");
        restTemplate.postForEntity("/api/auth/signUp", signUpRequest, Void.class);

        SignInRequest signInRequest = new SignInRequest("validateuser@example.com", "password123");
        ResponseEntity<JwtAuthenticationResponse> signInResponse = restTemplate.postForEntity("/api/auth/signIn", signInRequest, JwtAuthenticationResponse.class);

        String accessToken = signInResponse.getBody().accessToken();
        ValidateTokenRequest validateRequest = new ValidateTokenRequest(accessToken);

        ResponseEntity<UserInfo> response = restTemplate.postForEntity("/api/auth/validate", validateRequest, UserInfo.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().email()).isEqualTo("validateuser@example.com");
        assertThat(response.getBody().roles()).contains(com.rabinchuk.authenticationservice.model.RoleType.ROLE_USER);
    }

    @Test
    @DisplayName("Create admin successful")
    public void createAdmin_whenRequestIsValid_shouldCreateAdminUserAndReturn201() {
        CreateAdminRequest adminRequest = new CreateAdminRequest("theadmin@example.com", "supersecretpass");

        ResponseEntity<Void> response = restTemplate.postForEntity("/api/auth/create-admin", adminRequest, Void.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        Optional<UserCredentials> savedAdmin = userCredentialsRepository.findByEmail("theadmin@example.com");
        assertThat(savedAdmin).isPresent();
        assertThat(savedAdmin.get().getRoles()).contains(com.rabinchuk.authenticationservice.model.RoleType.ROLE_ADMIN);
    }

}
