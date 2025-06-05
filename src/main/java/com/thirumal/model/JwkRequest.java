package com.thirumal.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
/**
 * @author Thirumal
 * @version 1.0
 * @since 2025-06-05
 */
@Getter@Setter
@NoArgsConstructor@AllArgsConstructor
@ToString@Builder
public class JwkRequest {
    
    private String kty;
    private String crv;
    private String x;
    private String y;
    private boolean ext;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<String> key_ops;

    public List<String> getKey_ops() {
        return key_ops != null ? key_ops : List.of();
    }


}
