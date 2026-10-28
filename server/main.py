from axfilter.app import config_from_env, create_app

app = create_app(config_from_env())
