package com.qring.gateway.redis;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j(topic = "RedisSubscriber Log")
public class RedisSubscriber {

    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;

    @PostConstruct
    public void subscribeToUserUpdates() {
        reactiveRedisTemplate.listenToChannel("user-modification-channel")
                .doOnNext(message -> {
                    String userId = message.getMessage();
                    log.info("회원 정보 업데이트 감지. Redis에서 userId={} 데이터를 만료합니다.", userId);

                    reactiveRedisTemplate.delete(userId)
                            .doOnSuccess(deleted -> log.info("Redis에서 userId={} 데이터 삭제 완료: {}", userId, deleted))
                            .subscribe();
                })
                .subscribe();
    }
}