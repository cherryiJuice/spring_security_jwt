package com.example.jwt.service;

import com.example.jwt.dto.JoinDto;
import com.example.jwt.entity.User;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class JoinService {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	public void join(JoinDto joinDto) {
		String username = joinDto.getUsername();
		String password = joinDto.getPassword();

		if(userRepository.existsByUsername(username)) {
			return;
		}
		User user = User.builder()
			.username(username)
			.password(bCryptPasswordEncoder.encode(password))
			.role("ROLE_USER").build();

		userRepository.save(user);
	}
}

//
//		UserEntity data = new UserEntity();
//
//		data.setUsername(username);
//		data.setPassword(bCryptPasswordEncoder.encode(password));
//		data.setRole("ROLE_ADMIN");
//
//		userRepository.save(data);
//	}
//}
