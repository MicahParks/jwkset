package jwksetcom

import (
	hhconst "github.com/MicahParks/httphandle/constant"
)

const (
	LinkGitHub      = "https://github.com/MicahParks/jwkset/blob/master/website/README.md"
	PathAPIInspect  = "/api/inspect"
	PathAPINewGen   = "/api/new-gen"
	PathAPIPemGen   = "/api/pem-gen"
	PathGenerate    = "/generate"
	PathInspect     = "/inspect"
	TemplateWrapper = "wrapper.gohtml"
)

type Link struct{}

func (l Link) GitHub() string {
	return LinkGitHub
}

type Path struct{}

func (p Path) APIInspect() string {
	return PathAPIInspect
}
func (p Path) APINewGen() string {
	return PathAPINewGen
}
func (p Path) APIPemGen() string {
	return PathAPIPemGen
}
func (p Path) Generate() string {
	return PathGenerate
}
func (p Path) Index() string {
	return hhconst.PathIndex
}
func (p Path) Inspect() string {
	return PathInspect
}
