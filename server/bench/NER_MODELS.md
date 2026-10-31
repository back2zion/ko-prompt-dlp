# 실모델 NER 벤치마크 가이드

규칙 기반 인식기의 이름/주소 재현율(현재 0.80 / 0.50)을 학습된 한국어 NER 모델로 끌어올리는 절차.
**모델 가중치 다운로드가 필요**하므로 HuggingFace 접근이 가능한 환경(로컬/사내 GPU/CI)에서 실행한다.

## 실행
```
pip install "axfilter[ner]"          # transformers + torch
axfilter bench --ner-model <모델명> --ner-threshold 0.5
```
`detect(text, extra=[TransformerNerRecognizer(<모델>)])`로도 파이프라인에 직접 결합된다.

## 권장 한국어 NER 모델 (예시 — 라이선스·정확도는 직접 확인)
| 모델 | 라벨 스킴 | 비고 |
|---|---|---|
| `monologg/koelectra-base-v3-naver-ner` | PS/LC/OG/DT/TI/QT | NAVER NER, 범용 |
| `Leo97/KoELECTRA-small-v3-modu-ner` | 모두의말뭉치 NER | 경량 |
| `KPF/KPF-bert-ner` | 언론진흥재단 | 기사 도메인 |

기본 라벨 매핑(`ner_models.DEFAULT_LABEL_MAP`): `PS/PER→NAME`, `LC/LOC→ADDRESS`.
다른 스킴이면 `TransformerNerRecognizer(model, label_map={...})`로 지정.

## 측정·기록
- `axfilter bench --ner-model ...`가 유형별 정밀도/재현율/F1을 출력.
- 규칙 단독 대비(이름 R0.80, 주소 R0.50) 재현율 상승폭과 **오탐 증가(정밀도 하락)**를 함께 기록할 것.
- 임계값(`--ner-threshold`)으로 정밀도/재현율 트레이드오프 조정.

## 결과 템플릿
```
모델: <이름>  / 임계값: <값>  / 데이터셋: bench/dataset.jsonl (+ 실데이터 N건)
         prec  recall  f1
NAME    _____  ______  ____   (규칙: 1.000 / 0.800 / 0.889)
ADDRESS _____  ______  ____   (규칙: 1.000 / 0.500 / 0.667)
OVERALL _____  ______  ____   (규칙: 1.000 / 0.857 / 0.923)
결론: 재현율 +__%p, 정밀도 __%p, 운영 임계값 권고 __
```

> 주의: 공개 벤치 데이터셋은 합성이다. 실제 운영 품질은 **사내 실데이터(비식별 후)**로 재측정해야 한다.
