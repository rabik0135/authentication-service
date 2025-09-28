package com.rabinchuk.authenticationservice.dto;

import com.rabinchuk.authenticationservice.model.RoleType;
import lombok.Builder;

import java.util.Set;

@Builder
public record UserInfo(
        String email,
        Set<RoleType> roles
) {
}
