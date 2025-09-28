package com.rabinchuk.authenticationservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.rabinchuk.authenticationservice.dto.CreateAdminRequest;
import com.rabinchuk.authenticationservice.dto.JwtAuthenticationResponse;
import com.rabinchuk.authenticationservice.dto.RefreshTokenRequest;
import com.rabinchuk.authenticationservice.dto.SignInRequest;
import com.rabinchuk.authenticationservice.dto.SignUpRequest;
import com.rabinchuk.authenticationservice.dto.ValidateTokenRequest;
import com.rabinchuk.authenticationservice.model.RoleType;
import com.rabinchuk.authenticationservice.model.UserCredentials;
import com.rabinchuk.authenticationservice.repository.RefreshTokenRepository;
import com.rabinchuk.authenticationservice.repository.UserCredentialsRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.LocalDate;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static java.lang.Thread.sleep;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AuthControllerIntegrationTest {

    @Container
    @ServiceConnection
    private static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:17");

    @RegisterExtension
    protected static WireMockExtension wireMock = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort())
            .build();

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("user-service.url", wireMock::baseUrl);
        registry.add("INTERNAL_KEY", () -> "test-key");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserCredentialsRepository userCredentialsRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @AfterEach
    void tearDown() {
        refreshTokenRepository.deleteAll();
        userCredentialsRepository.deleteAll();
        wireMock.resetAll();
    }

    @Test
    @DisplayName("Sign up successful")
    public void signUp_whenValidRequest_shouldCreateUserAndReturn201() throws Exception {
        stubUserClient();

        mockMvc.perform(post("/api/auth/signUp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createSignUpRequest())))
                .andExpect(status().isCreated());

        assertThat(userCredentialsRepository.findByEmail("test.example@example.com")).isPresent();
        wireMock.verify(postRequestedFor(urlPathEqualTo("/api/users")));
    }

    @Test
    @DisplayName("Sign up with invalid email")
    public void signUp_whenEmailAlreadyExists_shouldReturn409() throws Exception {
        stubUserClient();
        mockMvc.perform(post("/api/auth/signUp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createSignUpRequest())))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/auth/signUp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createSignUpRequest())))
                .andExpect(status().isConflict());
    }


    @Test
    @DisplayName("Sign in successful")
    public void signIn_whenCredentialsAreValid_shouldReturnTokensAnd200() throws Exception {
        stubUserClient();
        mockMvc.perform(post("/api/auth/signUp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createSignUpRequest())))
                .andExpect(status().isCreated());

        SignInRequest signInRequest = new SignInRequest("test.example@example.com", "password123");

        mockMvc.perform(post("/api/auth/signIn")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString());
    }


    @Test
    @DisplayName("Sign in with invalid password")
    public void signIn_whenPasswordIsInvalid_shouldReturn401() throws Exception {
        stubUserClient();
        mockMvc.perform(post("/api/auth/signUp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createSignUpRequest())))
                .andExpect(status().isCreated());

        SignInRequest signInRequest = new SignInRequest("test.example@example.com", "wrong-password");

        mockMvc.perform(post("/api/auth/signIn")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Refresh token successful")
    public void refreshToken_whenTokenIsValid_shouldReturnNewAccessToken() throws Exception {
        JwtAuthenticationResponse signInResponse = signIpAndSignIn();
        String refreshToken = signInResponse.refreshToken();
        String oldAccessToken = signInResponse.accessToken();

        sleep(1000);

        RefreshTokenRequest refreshRequest = new RefreshTokenRequest(refreshToken);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken").value(refreshToken))
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.accessToken").value(not(equalTo(oldAccessToken))));
    }


    @Test
    @DisplayName("Validate token successful")
    public void validateToken_whenTokenIsValid_shouldReturnUserInfoAnd200() throws Exception {
        JwtAuthenticationResponse signInResponse = signIpAndSignIn();

        ValidateTokenRequest validateRequest = new ValidateTokenRequest(signInResponse.accessToken());

        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validateRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("test.example@example.com"))
                .andExpect(jsonPath("$.roles[0]").value(RoleType.ROLE_USER.name()));
    }

    @Test
    @DisplayName("Create admin successful")
    public void createAdmin_whenRequestIsValid_shouldCreateAdminUserAndReturn201() throws Exception {
        CreateAdminRequest adminRequest = new CreateAdminRequest("theadmin@example.com", "supersecretpass");

        mockMvc.perform(post("/api/auth/create-admin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(adminRequest)))
                .andExpect(status().isCreated());

        Optional<UserCredentials> savedAdmin = userCredentialsRepository.findByEmail("theadmin@example.com");
        assertThat(savedAdmin).isPresent();
        assertThat(savedAdmin.get().getRoles()).contains(com.rabinchuk.authenticationservice.model.RoleType.ROLE_ADMIN);
    }

    private void stubUserClient() {
        wireMock.stubFor(WireMock.post(urlPathEqualTo("/api/users"))
                .willReturn(aResponse()
                        .withStatus(201)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "id": "1",
                                  "name": "name",
                                  "surname": "surname",
                                  "birthDate": "1980-01-01",
                                  "email": "test.example@example.com"
                                }
                                """
                        )
                )
        );
    }

    private SignUpRequest createSignUpRequest() {
        return SignUpRequest.builder()
                .email("test.example@example.com")
                .password("password123")
                .name("name")
                .surname("surname")
                .birthDate(LocalDate.of(1980, 1, 1))
                .build();
    }

    private JwtAuthenticationResponse signIpAndSignIn() throws Exception {
        stubUserClient();
        mockMvc.perform(post("/api/auth/signUp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createSignUpRequest())))
                .andExpect(status().isCreated());

        SignInRequest signInRequest = new SignInRequest("test.example@example.com", "password123");
        MvcResult signInResult = mockMvc.perform(post("/api/auth/signIn")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signInRequest)))
                .andReturn();

        return objectMapper.readValue(signInResult.getResponse().getContentAsString(), JwtAuthenticationResponse.class);
    }

}
