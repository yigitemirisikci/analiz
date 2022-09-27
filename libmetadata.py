from typing import List


class Version:
    def __init__(self, d: dict = None) -> None:
        self.version = ""
        self.usages = 0
        self.date = "not found"
        self.filetype = ""  # <aar|jar>
        self.downloaded = False
        self.applied_analyzes: List[str] = []

        if d is not None:
            for key, value in d.items():
                setattr(self, key, value)

    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Version) and self.version == __o.version

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)

    def __hash__(self) -> int:
        return hash(self.version)


class Repo:
    def __init__(self, d: dict = None) -> None:
        self.name = ""
        self.base_url = ""
        self.versions: List[Version] = []

        if d is not None:
            for key, value in d.items():
                if key == "versions":
                    setattr(self, key, [Version(x) for x in value])
                else:
                    setattr(self, key, value)

    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Repo) and self.base_url == __o.base_url

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)

    def __hash__(self) -> int:
        return hash(self.base_url)

    def serialize(self) -> dict:
        return dict(name=self.name, base_url=self.base_url,
                    versions=[vars(v) for v in self.versions])

    def get_version(self, version: str) -> Version:
        for v in self.versions:
            if v.version == version:
                return v


class LibMetadata:
    def __init__(self, d: dict = None) -> None:
        self.id = ""
        self.artifact_id = ""
        self.group_id = ""
        self.tag = ""
        self.repos: List[Repo] = []

        if d is not None:
            for key, value in d.items():
                if key == "repos":
                    setattr(self, key, [Repo(x) for x in value])
                else:
                    setattr(self, key, value)

    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, LibMetadata) and self.id == __o.id

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)

    def __hash__(self) -> int:
        return hash(self.id)

    def serialize(self) -> dict:
        return dict(id=self.id, artifact_id=self.artifact_id, group_id=self.group_id,
                    tag=self.tag, repos=[r.serialize() for r in self.repos])

    def get_repo(self, repo_name: str) -> Repo:
        for repo in self.repos:
            if repo.name == repo_name:
                return repo