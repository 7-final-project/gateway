package com.qring.gateway.filter.pre;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;

@Component
@RequiredArgsConstructor
@Slf4j(topic = "JWT 검증 및 인가")
public class JwtAuthorizationFilter implements GlobalFilter, Ordered {

    private final MeterRegistry meterRegistry;


    // Header KEY 값
    public static final String AUTHORIZATION_HEADER = "Authorization";

    // Token 식별자
    public static final String BEARER_PREFIX = "Bearer ";

    @Value("${service.jwt.secret-key}")
    private String secretKey;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        log.info("Path 확인");
        if (path.equals("/v1/auth/login") || path.equals("/v1/users/join")) {
            log.info("요청 URI가 인증/인가 제외 경로입니다. 필터를 통과합니다.");
            return chain.filter(exchange);
        }

        log.info("Authorization 헤더에서 JWT 토큰 추출 시도");
        String token = getJwtFromHeader(exchange);

        if (token == null || !validateToken(token)) {
            log.warn("JWT 토큰이 유효하지 않습니다. 요청을 차단합니다.");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String userId = getUserIdFromToken(token);

        log.info("JWT 토큰 검증 성공: Passport 발급");

        // Timer 시작
        Timer.Sample sample = Timer.start(meterRegistry);

        return addPassportToken(exchange, userId)
                .flatMap(updatedExchange -> {
                    sample.stop(Timer.builder("passport.request.time") // Timer 종료
                            .description("Passport 발급 요청 소요 시간")
                            .tag("method", "direct")
                            .register(meterRegistry));
                    return chain.filter(updatedExchange);
                });
    }

    private String getJwtFromHeader(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            log.debug("Authorization 헤더에서 Bearer 토큰 추출 성공");
            return bearerToken.substring(7);
        }

        log.warn("Authorization 헤더가 없거나 잘못된 형식입니다.");
        return null;
    }

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

    private Jws<Claims> getClaimsJws(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }

    private String getUserIdFromToken(String token) {
        Jws<Claims> claimsJws = getClaimsJws(token);
        return String.valueOf(claimsJws.getBody().get("userId", Long.class));
    }

    private Mono<ServerWebExchange> addPassportToken(ServerWebExchange exchange, String userId) {

        WebClient webClient = WebClient.builder()
                .baseUrl("http://localhost:19005")
                .build();

        return webClient.post()
                .uri("/v1/auth/passport")
                .header("X-User-Id", userId)
                .retrieve()
                .bodyToMono(String.class)
                .map(passportToken -> {
                    ServerHttpRequest updatedRequest = exchange.getRequest()
                            .mutate()
                            .header("X-Passport-Token", passportToken)
                            .build();

                    return exchange.mutate()
                            .request(updatedRequest)
                            .build();
                });
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
