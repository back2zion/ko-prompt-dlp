"""Generate a labeled benchmark dataset with exact gold spans.

All values are synthetic (random/fictional); no real personal data is used.
Spans are computed as text is assembled, so labels are exact by construction.
Run: python bench/make_dataset.py > bench/dataset.jsonl
"""
import json
import random

rnd = random.Random(20261031)


def valid_rrn():
    base = f"{rnd.randint(70,99):02d}{rnd.randint(1,12):02d}{rnd.randint(1,28):02d}" \
           f"{rnd.randint(1,2)}{rnd.randint(0,99):06d}"[:12]
    w = [2,3,4,5,6,7,8,9,2,3,4,5]
    c = (11 - sum(int(a)*b for a,b in zip(base,w))%11)%10
    d = base+str(c)
    return d[:6]+"-"+d[6:]


def valid_card():
    while True:
        d=[rnd.randint(0,9) for _ in range(16)]; d[0]=4
        t=0
        for i,x in enumerate(reversed(d)):
            x = x*2 if i%2 else x
            t += x-9 if x>9 else x
        if t%10==0:
            s="".join(map(str,d)); return f"{s[:4]} {s[4:8]} {s[8:12]} {s[12:]}"


def valid_bizno():
    d=[rnd.randint(0,9) for _ in range(9)]
    w=[1,3,7,1,3,7,1,3,5]; su=sum(a*b for a,b in zip(d,w))+(d[8]*5)//10
    c=(10-su%10)%10; s="".join(map(str,d))+str(c)
    return f"{s[:3]}-{s[3:5]}-{s[5:]}"


def phone(): return f"010-{rnd.randint(1000,9999)}-{rnd.randint(1000,9999)}"
def email(): return rnd.choice(["hong","kim","park","lee","yoon"])+str(rnd.randint(1,99))+"@"+rnd.choice(["example.com","test.co.kr","corp.local"])
def passport(): return rnd.choice("MSRODG")+f"{rnd.randint(10**7,10**8-1)}"
def secret(): return rnd.choice([f"AKIA{''.join(rnd.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') for _ in range(16))}",
                                 "ghp_"+''.join(rnd.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(36)),
                                 "password = "+''.join(rnd.choice('abcdefghijklmnopqrstuvwxyz0123456789!@#') for _ in range(10))])

SUR=["김","이","박","최","정","강","조","윤","장","한","오","서","신","권","황","안","송"]
GIV=["민수","서준","지은","유리","하늘","도윤","수아","지호","예준","서연"]
def name(): return rnd.choice(SUR)+rnd.choice(GIV)
NAME_CUE=["이름: {n}","담당자 {n}","신청인 {n}","예약자 {n}","작성자는 {n}"]
NAME_HON=["{n}님","{n} 과장","{n} 팀장","{n}씨","{n} 대리"]

SIDO=["서울특별시","부산광역시","경기도","인천광역시","대전광역시"]
GUGUN=["강남구","해운대구","분당구","남동구","유성구"]
ROAD=["테헤란로","센텀로","판교로","논현로","대학로"]
def address(): return f"{rnd.choice(SIDO)} {rnd.choice(GUGUN)} {rnd.choice(ROAD)} {rnd.randint(1,500)}"

POS = {
    "RRN": (valid_rrn, ["고객 주민번호 {v} 확인 바랍니다","{v} 로 가입되어 있습니다"]),
    "CARD": (valid_card, ["결제 카드 {v} 승인","카드번호 {v} 등록"]),
    "PHONE": (phone, ["연락 {v} 로 부탁","휴대폰 {v}"]),
    "EMAIL": (email, ["회신은 {v} 로","메일 {v} 참고"]),
    "BIZNO": (valid_bizno, ["사업자등록번호 {v}","{v} 세금계산서"]),
    "PASSPORT": (passport, ["여권번호 {v} 입니다","{v} 로 발권"]),
    "SECRET": (secret, ["설정에 {v} 가 있었음","키 {v} 노출"]),
    "NAME": (name, NAME_CUE+NAME_HON),
    "ADDRESS": (address, ["배송지 {v}","{v} 로 방문"]),
}

NEG = ["2026년 10월 매출은 12,345,678원입니다","주문번호 20261028-ABX 처리 완료",
       "김밥 정말 맛있게 먹었다","조금 이따 회의 시작합니다","박스 300개 발주",
       "분기 실적을 요약해줘","이 코드 리뷰 좀 해줘","정말 수고 많으셨습니다",
       "서울 날씨가 좋네요","제품 사양을 표로 정리","회의는 3시에 시작","버전 2.0 배포 완료",
       "강수확률 60% 예보","이것은 테스트 문장","성공적으로 완료되었습니다"]

rows=[]
for typ,(gen,tmpls) in POS.items():
    for tm in tmpls:
        for _ in range(3):
            v=gen()
            text=tm.format(v=v, n=v)
            idx=text.find(v)
            rows.append({"text":text, "spans":[{"start":idx,"end":idx+len(v),"type":typ}]})
# a few multi-entity rows
for _ in range(6):
    n,p=name(),phone()
    t=f"담당자 {n} 연락처 {p}"
    rows.append({"text":t,"spans":[
        {"start":t.find(n),"end":t.find(n)+len(n),"type":"NAME"},
        {"start":t.find(p),"end":t.find(p)+len(p),"type":"PHONE"}]})
for neg in NEG:
    rows.append({"text":neg,"spans":[]})

# ---- hard slice: realistic misses and false-positive traps ----
# bare names without any cue/honorific — precision-first design misses these (FN)
for _ in range(9):
    n=name()
    tm=rnd.choice(["{n}가 보고서를 작성했습니다","{n}와 점심 약속","{n}한테 전달했어요"])
    t=tm.format(n=n)
    rows.append({"text":t,"spans":[{"start":t.find(n),"end":t.find(n)+len(n),"type":"NAME"}]})
# title + 님: look like surname+syllable but are roles, not names (must NOT fire)
for neg in ["이사님께 보고드립니다","부장님 지시사항 전달","과장님 확인 요망","팀장님 회의 소집","대표님 승인 완료","사장님 일정 공유"]:
    rows.append({"text":neg,"spans":[]})
# free-form road addresses without 시/군/구 — current regex misses (FN)
for _ in range(6):
    a=f"{rnd.choice(ROAD)} {rnd.randint(1,99)}길 {rnd.randint(1,50)}"
    rows.append({"text":f"배송지는 {a} 입니다","spans":[{"start":len('배송지는 '),"end":len('배송지는 ')+len(a),"type":"ADDRESS"}]})
# address-ish negatives (place name only, not an address)
for neg in ["강남 맛집 추천해줘","서울 날씨가 맑음","부산 여행 계획"]:
    rows.append({"text":neg,"spans":[]})

rnd.shuffle(rows)
for r in rows:
    print(json.dumps(r, ensure_ascii=False))
