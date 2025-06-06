package com.thirumal.model;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter @Setter 
@NoArgsConstructor @AllArgsConstructor
@ToString@Builder
public class EncryptedMessage {
    private List<Integer> ciphertext;
    private List<Integer> iv;
}
