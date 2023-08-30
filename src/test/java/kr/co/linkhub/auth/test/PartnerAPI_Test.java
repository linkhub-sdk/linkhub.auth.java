package kr.co.linkhub.auth.test;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import kr.co.linkhub.auth.LinkhubException;
import kr.co.linkhub.auth.MemberPointInfo;
import kr.co.linkhub.auth.Token;
import kr.co.linkhub.auth.TokenBuilder;

public class PartnerAPI_Test {
	
	private final String LinkID = "TESTER";
    private final String SecretKey = "SwWxqU+0TErBXy/9TVjIPEnI0VTUMMSQZtJf3Ed8q3I=";
    
	@Test
    public void PartnerMemberPointList() throws LinkhubException {
		
		TokenBuilder tokenBuilder = 
				TokenBuilder.newInstance(LinkID, SecretKey) // LinkID, SecretKey는 발급받은 인증정보로 기재
				.ServiceID("POPBILL_TEST")  // 운용환경은 "POPBILL", 테스트환경은 "POPBILL_TEST" 기재
				.addScope("partner")        // 회원목록을 응답받기위해 "member"아닌 "partner" 기재
				.addScope("110");           // 전자세금계산서 아이템코드 "110" 기재
				
	
		Token token = tokenBuilder.build();
		
		assertNotNull(token.getSession_token());
		
		// 조회할 연동회원 사업자 배열, 최대 100건-초과시 오류발생..
		// 100건중 가입된 회원사업자번호가 아닌경우 응답 배열에서 제외됨.
		String[] MemberCorpNums = new String[]{
				"6798700433","2198110402","4108600477","4091012658","1341986415",
				"1231212312","2222222222","1111111111","1212062413","2309823538",
				"1318607714","4040683485","6210450455","2102360093","1234567890",
				"1208795568","3852012399","2258110770","3071033094","6473300302",
				"3062772165","3164900035","1078628206","1023958230","2309582351",
				"4364364331","2030273881","2309482392","2305982300","2352345320",
				"3029482305","2309580921","000-00-00900	","123-45-67800	"};
		
		MemberPointInfo[] pointInfo = null;
		
		try {
			// 회원 포인트 목록 조회 함수 호출.
			pointInfo = tokenBuilder.listMemberPointInfo(token.getSession_token(), MemberCorpNums);
		} catch (LinkhubException e) {
			System.out.println(e.getCode());
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		
		
		System.out.println(pointInfo.length);
		
		for(int i=0; i< pointInfo.length; i++) {
			
			// 응답항목
			// CorpNum - 사업자번호
			// RealPoint - 회원이 결제한 포인트.
			// BonusPoint - 가입이벤트로 충전된 보너스 포인트
			System.out.println(pointInfo[i].getCorpNum() +" / " +pointInfo[i].getRealPoint() + " / "+ pointInfo[i].getBonusPoint());
		}
		
	}
}
