package com.sparta.and.service;

import com.sparta.and.dto.request.SearchRequestDto;
import com.sparta.and.dto.request.ContestRequestDto;
import com.sparta.and.dto.response.ContestResponseDto;
import com.sparta.and.entity.Contest;
import com.sparta.and.repository.ContestRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@RequiredArgsConstructor
@Service
public class ContestService {

	private final ContestRepository contestRepository;

	public List<ContestResponseDto> getContests() {
		return contestRepository.findAllByOrderByCreatedDateDesc().stream().map(ContestResponseDto::new).toList();
	}

	public ContestResponseDto createContest(ContestRequestDto requestDto) {
		Contest createContest = new Contest(requestDto);
		contestRepository.save(createContest);

		return new ContestResponseDto(createContest);
	}

	public List<ContestResponseDto> searchContest(SearchRequestDto requestDto) {
		if (requestDto.getKeyword().isBlank()) {
			return getContests();
		}

		List<ContestResponseDto> list = contestRepository.findByTitleContaining(
				requestDto.getKeyword()).stream().map(ContestResponseDto::new).toList();

		if (list.isEmpty()) {
			throw new IllegalArgumentException("해당 검색결과가 없습니다.");
		}

		return list;
	}
}
