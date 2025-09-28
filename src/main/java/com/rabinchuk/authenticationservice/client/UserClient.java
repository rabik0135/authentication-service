package com.rabinchuk.authenticationservice.client;

import com.rabinchuk.authenticationservice.dto.SignUpUserRequest;
import com.rabinchuk.authenticationservice.dto.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service", url = "${user-service.url}")
public interface UserClient {

    @PostMapping("/api/users")
    UserResponse createUser(@RequestBody SignUpUserRequest signUpUserRequest);

    @DeleteMapping("/api/users/{userId}")
    void deleteUser(@PathVariable Long userId);
}
