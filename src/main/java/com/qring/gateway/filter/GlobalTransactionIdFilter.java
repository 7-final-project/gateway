package com.qring.gateway.filter;

import com.github.f4b6a3.tsid.TsidCreator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;


@Component
@Slf4j(topic = "GlobalTransactionIdFilter")
public class GlobalTransactionIdFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String transactionId = TsidCreator.getTsid1024().toString();

        ServerHttpRequest updatedRequest = exchange.getRequest()
                .mutate()
                .header("GLBL-TRX-ID", transactionId)
                .build();

        return chain.filter(exchange.mutate().request(updatedRequest).build())
                .contextWrite(Context.of("glbl_trx_id", transactionId));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
