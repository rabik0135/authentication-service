FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

FROM bellsoft/liberica-openjre-alpine:21-cds
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8082
RUN apk add --no-cache curl
ENTRYPOINT ["java", "-jar", "app.jar"]