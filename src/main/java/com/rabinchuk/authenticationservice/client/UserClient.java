package com.rabinchuk.authenticationservice.client;

import com.rabinchuk.authenticationservice.dto.SignUpUserRequestDto;
import com.rabinchuk.authenticationservice.dto.UserResponseDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service", url = "${user-service.url}")
public interface UserClient {

    @PostMapping("/api/users")
    UserResponseDto createUser(@RequestBody SignUpUserRequestDto signUpUserRequestDto);

    @DeleteMapping("/api/users/{userId}")
    void deleteUser(@PathVariable Long userId);
}
