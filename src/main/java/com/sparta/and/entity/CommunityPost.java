package com.sparta.and.entity;

import com.sparta.and.dto.CommunityPostRequestDto;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.DynamicInsert;

@Entity
@Getter
@Setter
@Table(name = "communityPost")
@DynamicInsert
@NoArgsConstructor
public class CommunityPost extends Timestamped {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long communityPostId;

	@Column(name = "title", nullable = false)
	private String title;

	@Column(name = "contents", nullable = false)
	private String contents;

	@Column(name = "communityPostViews")
	@ColumnDefault("0")
	// 조회수 디폴트 값을 0으로 주긴 했는데 좋아요 카운트 했던 것처럼 증가, 감소 메서드를 만들어야 하는 건지 잘 모르겠어요...
	private Long communityPostViews;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "userId")
	private User user;

	public CommunityPost(CommunityPostRequestDto requestDto) {
		this.title = requestDto.getTitle();
		this.contents = requestDto.getContents();
//		this.user = user;
	}
}
