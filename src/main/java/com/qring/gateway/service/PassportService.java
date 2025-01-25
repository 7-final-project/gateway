package com.qring.gateway.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Service
@RequiredArgsConstructor
@Slf4j(topic = "PassportService")
public class PassportService {
    // 도커 이미지 최신화 테스트

    @Value("${auth-service.base-url}")
    private String authServiceBaseUrl;

    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;

    // -----
    // NOTE: Redis에서 Passport Token을 가져오거나, 없으면 새로 발급하는 메서드
    public Mono<String> getOrCreatePassport(String userId) {
        return reactiveRedisTemplate.opsForValue()
                .get(userId)
                .switchIfEmpty(Mono.defer(() -> {
                    log.info("Redis에 Passport Token 없음. 새로운 Passport 발급 시도");
                    return requestNewPassport(userId)
                            .flatMap(newPassport -> reactiveRedisTemplate.opsForValue()
                                    .set(userId, newPassport, Duration.ofMinutes(5))
                                    .thenReturn(newPassport));
                }))
                .doOnSuccess(passport -> log.info("Redis에서 Passport Token 조회 성공"))
                .doOnError(e -> log.error("Passport 조회 중 오류 발생: {}", e.getMessage()));
    }

    // -----
    // NOTE: 새로운 Passport Token 발급 요청
    private Mono<String> requestNewPassport(String userId) {
        return WebClient.create(authServiceBaseUrl)
                .post()
                .uri("/v1/auth/passport")
                .header("X-User-Id", userId)
                .retrieve()
                .bodyToMono(String.class)
                .doOnSuccess(passport -> log.info("새로운 Passport 발급 성공"))
                .doOnError(e -> log.error("Passport 발급 실패: {}", e.getMessage()));
    }
}
