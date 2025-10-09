package com.rabinchuk.authenticationservice.repository;

import com.rabinchuk.authenticationservice.model.RefreshToken;
import com.rabinchuk.authenticationservice.model.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    void deleteByUserCredentials(UserCredentials userCredentials);

}
