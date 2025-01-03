package com.qring.gateway.filter.pre.v2;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.time.Duration;

@Component
@RequiredArgsConstructor
@Slf4j(topic = "JwtAuthorizationFilterV2 Log")
@ConditionalOnProperty(name = "filter.v2.enabled", havingValue = "true", matchIfMissing = true)
public class JwtAuthorizationFilterV2 implements GlobalFilter, Ordered {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;

    @Value("${service.jwt.secret-key}")
    private String secretKey;

    //---
    // NOTE: 필터 시작 로직
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (path.equals("/v1/auth/login") || path.equals("/v1/users/join")) {
            log.info("인증/인가 제외 경로. 필터를 통과합니다.");
            return chain.filter(exchange);
        }

        String token = getJwtFromHeader(exchange);
        if (token == null || !validateToken(token)) {

            log.warn("유효하지 않은 JWT 토큰입니다. 요청을 차단합니다.");

            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String userId = getUserIdFromToken(token);

        log.info("JWT 토큰 검증 성공. Redis에서 Passport 확인");
        return getOrCreatePassport(userId)
                .flatMap(passportToken -> addPassportToRequest(exchange, passportToken))
                .flatMap(chain::filter);
    }

    //---
    // NOTE: Authorization 헤더에서 JWT 토큰 추출하는 메서드
    private String getJwtFromHeader(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        log.warn("Authorization 헤더가 없거나 잘못된 형식입니다.");
        return null;
    }

    // -----
    // NOTE: JWT 토큰 유효성 검증
    private boolean validateToken(String token) {
        try {
            getClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException | SignatureException e) {
            log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token, 만료된 JWT token 입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
        }
        return false;
    }

    // -----
    // NOTE: JWT 토큰에서 Claims 추출
    private Jws<Claims> getClaimsJws(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
    }

    // -----
    // NOTE: JWT 토큰에서 userId 추출
    private String getUserIdFromToken(String token) {
        Jws<Claims> claimsJws = getClaimsJws(token);
        return String.valueOf(claimsJws.getBody().get("userId", Long.class));
    }

    // -----
    // NOTE: Redis에서 Passport Token을 가져오거나, 없으면 새로 발급하는 메서드
    public Mono<String> getOrCreatePassport(String userId) {
        return reactiveRedisTemplate.opsForValue()
                .get(userId)
                .switchIfEmpty(Mono.defer(() -> requestNewPassport(userId)
                        .flatMap(newPassport -> reactiveRedisTemplate.opsForValue()
                                .set(userId, newPassport, Duration.ofMinutes(5))
                                .thenReturn(newPassport))))
                .doOnSuccess(passport -> log.info("Redis에서 Passport Token 조회 성공: {}", passport));
    }

    // -----
    // NOTE: 새로운 Passport Token 발급 요청
    private Mono<String> requestNewPassport(String userId) {
        return WebClient.create("http://localhost:19005")
                .post()
                .uri("/v1/auth/passport")
                .header("X-User-Id", userId)
                .retrieve()
                .bodyToMono(String.class)
                .doOnError(e -> log.error("Passport 발급 실패: {}", e.getMessage()));
    }

    // -----
    // NOTE: Passport Token을 요청에 추가
    private Mono<ServerWebExchange> addPassportToRequest(ServerWebExchange exchange, String passportToken) {
        ServerHttpRequest updatedRequest = exchange.getRequest()
                .mutate()
                .header("X-Passport-Token", passportToken)
                .build();
        return Mono.just(exchange.mutate().request(updatedRequest).build());
    }

    // -----
    // NOTE: 필터의 실행 순서를 결정
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
