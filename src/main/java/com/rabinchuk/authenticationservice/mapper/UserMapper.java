package com.rabinchuk.authenticationservice.mapper;

import com.rabinchuk.authenticationservice.dto.SignUpRequestDto;
import com.rabinchuk.authenticationservice.dto.SignUpUserRequestDto;
import com.rabinchuk.authenticationservice.model.RoleType;
import com.rabinchuk.authenticationservice.model.UserCredentials;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.Set;

@Mapper(componentModel = "spring", imports = {Set.class, RoleType.class})
public interface UserMapper {

    SignUpUserRequestDto toSignUpUserRequest(SignUpRequestDto signUpRequestDto);

    @Mapping(target = "roles", expression = "java(Set.of(RoleType.ROLE_USER))")
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "password", ignore = true)
    UserCredentials toUserCredentials(SignUpRequestDto signUpRequestDto);

}
