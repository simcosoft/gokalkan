package gokalkan

import "github.com/simcosoft/gokalkan/ckalkan"

// Underlying возвращает текущий ckalkan.Client, используемый клиентом gokalkan.
func (cli *Client) Underlying() *ckalkan.Client {
	return cli.kc
}
