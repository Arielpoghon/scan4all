package Configs

// payload in json mode
type ExpJson struct {
	Name        string `json:"Name"`
	Description string `json:"Description"`
	Product     string `json:"Product"`
	Author      string `json:"author"`

	// request data
	// as can be seen, this simple definition is still inferior to nuclei, the relationships between multiple requests cannot be expressed with semicolons
	Request []struct {
		Method           string            `json:"Method"`
		Header           map[string]string `json:"Header"`
		Uri              string            `json:"Uri"`
		Port             string            `json:"Port"`
		Data             string            `json:"Data"`
		Follow_redirects string            `json:"Follow_redirects"`
		// file upload
		Upload struct {
			Name     string `json:"Name"`
			FileName string `json:"fileName"`
			FilePath string `json:"FilePath"`
		} `json:"Upload"`
		// response
		Response struct {
			Check_Steps string `json:"Check_Steps"`
			Checks      []struct {
				Operation string `json:"Operation"`
				Key       string `json:"Key"`
				Value     string `json:"Value"`
			} `json:"Checks"`
		}
		Search      string `json:"Search"`
		Next_decide string `json:"Next_decide"`
	} `json:"Request"`
}

type ConfigJson struct {
	Exploit struct {
		Path string `json:"Path"`
	} `json:"Exploit"`
}

type UserOption struct {
	OriAddr   string // original address
	UriAddr   string // address after concatenating Uri parameters
	JsonFile  string // configured json document
	AllJson   bool   // use all json files, i.e. run all vulnerabilities
	KeyWord   string // search keyword
	File      string // read urls from file
	ThreadNum int    // define number of threads
	GetTitle  bool   // specifically for getting url titles

}

type HttpResult struct {
	Resp *[]byte
	Body string
}

type FileNameStruct struct { // used to receive parameters such as file name
	Name     string
	Filename string
	FilePath string
}
